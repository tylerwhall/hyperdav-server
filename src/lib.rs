//! WebDAV server as a hyper server handler
//!
//!```no_run
//!extern crate hyper;
//!extern crate hyperdav_server;
//!
//!let server = hyper::server::Server::http("0.0.0.0:8080").unwrap();
//!server
//!    .handle(hyperdav_server::Server::new("", std::path::Path::new("/")))
//!    .unwrap();
//!```
extern crate chrono;
extern crate hyper;
#[macro_use]
extern crate log;
extern crate url;
extern crate xml;

use std::borrow::{Borrow, Cow};
use std::time::{UNIX_EPOCH, SystemTime};
use std::io::{self, Read, Write, ErrorKind};
use std::fs::{self, Metadata, read_dir, File};
use std::path::{Path, PathBuf};

use hyper::header::ContentLength;
use hyper::method::Method;
use hyper::server::{Handler, Request, Response};
use hyper::status::StatusCode;
use hyper::uri::RequestUri;
use xml::{EmitterConfig, ParserConfig};
use xml::common::XmlVersion;
use xml::name::{Name, OwnedName};
use xml::reader::XmlEvent;
use xml::writer::EventWriter;
use xml::writer::XmlEvent as XmlWEvent;

struct ServerPath {
    // HTTP path on the server representing the root directory
    url_prefix: Cow<'static, str>,
    // Root file system directory of the server
    srv_root: Cow<'static, Path>,
}

impl ServerPath {
    // Ex. url_prefix = "/dav", srv_root = "/srv/dav/"
    fn new<U, R>(url_prefix: U, srv_root: R) -> Self
        where U: Into<Cow<'static, str>>, R: Into<Cow<'static, Path>> {
        let url_prefix = url_prefix.into();
        let srv_root = srv_root.into();

        assert_eq!(url_prefix.trim_right_matches("/"), url_prefix);
        assert!(srv_root.ends_with("/"));

        ServerPath {
            url_prefix: url_prefix,
            srv_root: srv_root,
        }
    }

    fn file_to_url<P: AsRef<Path>>(&self, path: P) -> String {
        let path = path.as_ref()
            .strip_prefix(&self.srv_root)
            .expect("file_to_url");
        self.url_prefix.clone().into_owned() + "/" + path.to_str().expect("file_to_url")
    }

    fn url_to_file<'a>(&'a self, url: &'a str) -> Option<PathBuf> {
        if url.starts_with(self.url_prefix.borrow() as &str) {
            let subpath = &url[self.url_prefix.len()..]
                               .trim_left_matches("/")
                               .trim_right_matches("/");
            let mut ret = self.srv_root.clone().into_owned();
            ret.push(subpath);
            Some(ret)
        } else {
            None
        }
    }
}

#[test]
fn test_serverpath() {
    let s = ServerPath::new("/dav", Path::new("/"));
    assert_eq!(s.url_to_file("/dav/foo").unwrap().to_str().unwrap(), "/foo");
    assert_eq!(s.url_to_file("/dav/foo/").unwrap().to_str().unwrap(),
               "/foo");
    assert_eq!(s.url_to_file("/dav/foo//").unwrap().to_str().unwrap(),
               "/foo");
    assert_eq!(s.url_to_file("/dav//foo//").unwrap().to_str().unwrap(),
               "/foo");
    assert_eq!(&s.file_to_url("/foo"), "/dav/foo");
    assert_eq!(&s.file_to_url("/"), "/dav/");
}

pub struct Server {
    serverpath: ServerPath,
}

impl Server {
    /// Create a WebDAV handler
    ///
    /// * `url_prefix` - the path on the server that maps to the WebDAV root. It
    /// must not end with trailing slashes.
    ///
    /// * `srv_root` - must be a directory on the host and must end with a trailing slash.
    ///
    /// Panics if the above requirements are not met.
    /// These requirements are desired to consistently map between server URLs
    /// and host file system paths. Since the server returns URLs for files,
    /// the mapping must be consistent in both directions.
    ///
    /// Ex. url_prefix = "/dav", srv_root = Path::new("/srv/dav/")
    pub fn new<U, R>(url_prefix: U, srv_root: R) -> Self
        where U: Into<Cow<'static, str>>, R: Into<Cow<'static, Path>> {
        Server { serverpath: ServerPath::new(url_prefix, srv_root) }
    }
}

#[derive(Debug)]
enum RequestType {
    Options,
    Propfind,
    Get,
    Copy,
    Move,
    Delete,
    Put,
    Mkdir,
}

#[derive(Debug)]
enum Error {
    ParseError,
    BadPath,
    XmlReader(xml::reader::Error),
    XmlWriter(xml::writer::Error),
    Io(io::Error),
}

impl From<xml::reader::Error> for Error {
    fn from(e: xml::reader::Error) -> Self {
        Error::XmlReader(e)
    }
}

impl From<xml::writer::Error> for Error {
    fn from(e: xml::writer::Error) -> Self {
        Error::XmlWriter(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

fn parse_propfind<R: Read, F: FnMut(OwnedName) -> ()>(mut xml: xml::reader::EventReader<R>,
                                                      mut f: F)
                                                      -> Result<(), Error> {
    enum State {
        Start,
        PropFind,
        Prop,
        InProp,
    }

    let mut state = State::Start;

    loop {
        let event = xml.next()?;
        match state {
            State::Start => {
                match event {
                    XmlEvent::StartDocument { .. } => (),
                    XmlEvent::StartElement { ref name, .. } if name.local_name == "propfind" => {
                        state = State::PropFind;
                    }
                    _ => return Err(Error::ParseError),
                }
            }
            State::PropFind => {
                match event {
                    XmlEvent::StartElement { ref name, .. } if name.local_name == "prop" => {
                        state = State::Prop;
                    }
                    _ => return Err(Error::ParseError),
                }
            }
            State::Prop => {
                match event {
                    XmlEvent::StartElement { name, .. } => {
                        state = State::InProp;
                        f(name);
                    }
                    XmlEvent::EndElement { .. } => {
                        return Ok(());
                    }
                    _ => return Err(Error::ParseError),
                }
            }
            State::InProp => {
                match event {
                    XmlEvent::EndElement { .. } => {
                        state = State::Prop;
                    }
                    _ => return Err(Error::ParseError),
                }
            }
        }
    }
}

fn write_client_prop<W: Write>(xmlwriter: &mut EventWriter<W>,
                               prop: Name)
                               -> Result<(), xml::writer::Error> {
    if let Some(namespace) = prop.namespace {
        if let Some(prefix) = prop.prefix {
            // Remap the client's prefix if it overlaps with our DAV: prefix
            if prefix == "D" && namespace != "DAV:" {
                let newname = Name {
                    local_name: prop.local_name,
                    namespace: Some(namespace),
                    prefix: Some("U"),
                };
                return xmlwriter.write(XmlWEvent::start_element(newname).ns("U", namespace));
            }
        }
    }
    xmlwriter.write(XmlWEvent::start_element(prop))
}

fn systime_to_format(time: SystemTime) -> String {
    use chrono::datetime::DateTime;
    use chrono::naive::datetime::NaiveDateTime;
    use chrono::offset::utc::UTC;

    let unix = time.duration_since(UNIX_EPOCH).unwrap();
    let time = DateTime::<UTC>::from_utc(NaiveDateTime::from_timestamp(unix.as_secs() as i64,
                                                                       unix.subsec_nanos()),
                                         UTC);
    time.to_rfc3339()
}

fn handle_prop_path<W: Write>(xmlwriter: &mut EventWriter<W>,
                              meta: &Metadata,
                              prop: Name)
                              -> Result<bool, Error> {
    match (prop.namespace, prop.local_name) {
        (Some("DAV:"), "resourcetype") => {
            xmlwriter.write(XmlWEvent::start_element("D:resourcetype"))?;
            if meta.is_dir() {
                xmlwriter.write(XmlWEvent::start_element("D:collection"))?;
                xmlwriter.write(XmlWEvent::end_element())?;
            }
            xmlwriter.write(XmlWEvent::end_element())?;
            Ok(true)
        }
        (Some("DAV:"), "creationdate") => {
            if let Ok(time) = meta.created() {
                xmlwriter.write(XmlWEvent::start_element("D:creationdate"))?;
                xmlwriter
                    .write(XmlWEvent::characters(&systime_to_format(time)))?;
                xmlwriter.write(XmlWEvent::end_element())?;
                Ok(true)
            } else {
                Ok(false)
            }
        }
        (Some("DAV:"), "getlastmodified") => {
            if let Ok(time) = meta.modified() {
                xmlwriter
                    .write(XmlWEvent::start_element("D:getlastmodified"))?;
                xmlwriter
                    .write(XmlWEvent::characters(&systime_to_format(time)))?;
                xmlwriter.write(XmlWEvent::end_element())?;
                Ok(true)
            } else {
                Ok(false)
            }
        }
        (Some("DAV:"), "getcontentlength") => {
            xmlwriter
                .write(XmlWEvent::start_element("D:getcontentlength"))?;
            xmlwriter
                .write(XmlWEvent::characters(&meta.len().to_string()))?;
            xmlwriter.write(XmlWEvent::end_element())?;
            Ok(true)
        }
        (Some("DAV:"), "getcontenttype") => {
            xmlwriter
                .write(XmlWEvent::start_element("D:getcontenttype"))?;
            if meta.is_dir() {
                xmlwriter
                    .write(XmlWEvent::characters("httpd/unix-directory"))?;
            } else {
                xmlwriter.write(XmlWEvent::characters("text/plain"))?;
            }
            xmlwriter.write(XmlWEvent::end_element())?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn handle_propfind_path<W: Write>(xmlwriter: &mut EventWriter<W>,
                                  url: &str,
                                  meta: &Metadata,
                                  props: &[OwnedName])
                                  -> Result<(), Error> {
    xmlwriter.write(XmlWEvent::start_element("D:response"))?;

    xmlwriter.write(XmlWEvent::start_element("D:href"))?;
    xmlwriter.write(XmlWEvent::characters(url))?;
    xmlwriter.write(XmlWEvent::end_element())?; // href

    let mut failed_props = Vec::with_capacity(props.len());
    xmlwriter.write(XmlWEvent::start_element("D:propstat"))?;
    xmlwriter.write(XmlWEvent::start_element("D:prop"))?;
    for prop in props {
        if !handle_prop_path(xmlwriter, meta, prop.borrow())? {
            failed_props.push(prop);
        }
    }
    xmlwriter.write(XmlWEvent::end_element())?; // prop
    xmlwriter.write(XmlWEvent::start_element("D:status"))?;
    if failed_props.len() >= props.len() {
        // If they all failed, make this a failure response and return
        xmlwriter
            .write(XmlWEvent::characters("HTTP/1.1 404 Not Found"))?;
        xmlwriter.write(XmlWEvent::end_element())?; // status
        xmlwriter.write(XmlWEvent::end_element())?; // propstat
        xmlwriter.write(XmlWEvent::end_element())?; // response
        return Ok(());
    }
    xmlwriter.write(XmlWEvent::characters("HTTP/1.1 200 OK"))?;
    xmlwriter.write(XmlWEvent::end_element())?; // status
    xmlwriter.write(XmlWEvent::end_element())?; // propstat

    // Handle the failed properties
    xmlwriter.write(XmlWEvent::start_element("D:propstat"))?;
    xmlwriter.write(XmlWEvent::start_element("D:prop"))?;
    for prop in failed_props {
        write_client_prop(xmlwriter, prop.borrow())?;
        xmlwriter.write(XmlWEvent::end_element())?;
    }
    xmlwriter.write(XmlWEvent::end_element())?; // prop
    xmlwriter.write(XmlWEvent::start_element("D:status"))?;
    xmlwriter
        .write(XmlWEvent::characters("HTTP/1.1 404 Not Found"))?;
    xmlwriter.write(XmlWEvent::end_element())?; // status
    xmlwriter.write(XmlWEvent::end_element())?; // propstat
    xmlwriter.write(XmlWEvent::end_element())?; // response
    Ok(())
}

fn io_error_to_status(e: io::Error, res: &mut Response<hyper::net::Fresh>) -> io::Error {
    if e.kind() == ErrorKind::NotFound {
        *res.status_mut() = StatusCode::NotFound;
    } else {
        *res.status_mut() = StatusCode::InternalServerError;
    }
    e
}

impl Server {
    fn handle_propfind_path_recursive<W: Write>(&self,
                                                path: &Path,
                                                depth: u32,
                                                xmlwriter: &mut EventWriter<W>,
                                                props: &[OwnedName])
                                                -> Result<(), Error> {
        if depth == 0 {
            return Ok(());
        }
        for f in read_dir(path)? {
            let f = match f {
                Ok(f) => f,
                Err(e) => {
                    error!("Read dir error. Skipping {:?}", e);
                    continue;
                }
            };
            let path = f.path();
            let meta = match f.metadata() {
                Ok(meta) => meta,
                Err(e) => {
                    error!("Metadata error on {:?}. Skipping {:?}", path, e);
                    continue;
                }
            };
            handle_propfind_path(xmlwriter, &self.serverpath.file_to_url(&path), &meta, props)?;
            // Ignore errors in order to try the other files. This could fail for
            // connection reasons (not file I/O), but those should retrigger and
            // get passed up on subsequent xml writes
            let _ = self.handle_propfind_path_recursive(&path, depth - 1, xmlwriter, props);
        }
        Ok(())
    }

    fn uri_to_path(&self,
                   req: &Request,
                   res: &mut Response<hyper::net::Fresh>)
                   -> Result<PathBuf, Error> {
        if let RequestUri::AbsolutePath(ref s) = req.uri {
                // Unwrap should hopefully be safe since we just came from a string
                let s = url::percent_encoding::percent_decode(s.as_bytes())
                    .decode_utf8()
                    .expect("percent decode");
                self.serverpath.url_to_file(s.borrow())
            } else {
                None
            }
            .ok_or_else(|| {
                            *res.status_mut() = StatusCode::NotFound;
                            Error::BadPath
                        })
    }

    fn uri_to_src_dst(&self,
                      req: &Request,
                      res: &mut Response<hyper::net::Fresh>)
                      -> Result<(PathBuf, PathBuf), Error> {
        // Get the source
        let src = self.uri_to_path(req, res)?;

        // Get the destination
        let dst = req.headers
            .get_raw("Destination")
            .and_then(|vec| vec.get(0))
            .and_then(|vec| std::str::from_utf8(vec).ok())
            .and_then(|s| url::Url::parse(s).ok())
            .ok_or(Error::BadPath)
            .map_err(|e| {
                         *res.status_mut() = StatusCode::BadRequest;
                         e
                     })?;
        let dst = url::percent_encoding::percent_decode(dst.path().as_bytes())
            .decode_utf8()
            .map_err(|_| Error::BadPath)
            .and_then(|dst| {
                          self.serverpath
                              .url_to_file(dst.borrow())
                              .ok_or(Error::BadPath)
                      })
            .map_err(|e| {
                         *res.status_mut() = StatusCode::BadRequest;
                         e
                     })?;

        if src == dst {
            *res.status_mut() == StatusCode::Forbidden;
            return Err(Error::BadPath);
        }

        Ok((src, dst))
    }

    fn handle_propfind(&self,
                       mut req: Request,
                       mut res: Response<hyper::net::Fresh>)
                       -> Result<(), Error> {
        // Get the file
        let path = self.uri_to_path(&req, &mut res)?;

        // Get the depth
        let depth = req.headers
            .get_raw("Depth")
            .and_then(|vec| vec.get(0))
            .and_then(|vec| std::str::from_utf8(vec).ok())
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);

        let xml = xml::reader::EventReader::new_with_config(&mut req,
                                                            ParserConfig {
                                                                trim_whitespace: true,
                                                                ..Default::default()
                                                            });
        let mut props = Vec::new();
        if let Err(e) = parse_propfind(xml, |prop| { props.push(prop); }) {
            *res.status_mut() = StatusCode::BadRequest;
            return Err(e);
        }

        debug!("Propfind {:?} {:?}", path, props);

        let meta = path.metadata()
            .map_err(|e| io_error_to_status(e, &mut res))?;
        *res.status_mut() = StatusCode::MultiStatus;

        let mut xmlwriter = EventWriter::new_with_config(res.start()?,
                                                         EmitterConfig {
                                                             perform_indent: true,
                                                             ..Default::default()
                                                         });
        xmlwriter
            .write(XmlWEvent::StartDocument {
                       version: XmlVersion::Version10,
                       encoding: Some("utf-8"),
                       standalone: None,
                   })?;
        xmlwriter
            .write(XmlWEvent::start_element("D:multistatus").ns("D", "DAV:"))?;

        handle_propfind_path(&mut xmlwriter,
                             &self.serverpath.file_to_url(&path),
                             &meta,
                             &props)?;

        if meta.is_dir() {
            self.handle_propfind_path_recursive(&path, depth, &mut xmlwriter, &props)?;
        }

        xmlwriter.write(XmlWEvent::end_element())?;
        Ok(())
    }

    fn handle_get(&self, req: Request, mut res: Response<hyper::net::Fresh>) -> Result<(), Error> {
        // Get the file
        let path = self.uri_to_path(&req, &mut res)?;
        let mut file = File::open(path)
            .map_err(|e| io_error_to_status(e, &mut res))?;
        let size = file.metadata()
            .map(|m| m.len())
            .map_err(|e| io_error_to_status(e, &mut res))?;

        // Ignore size = 0 to hopefully work reasonably with special files
        if size > 0 {
            res.headers_mut().set(ContentLength(size))
        }

        // TODO: byte ranges (Accept-Ranges: bytes)
        io::copy(&mut file, &mut res.start()?)?;
        Ok(())
    }

    fn handle_put(&self,
                  mut req: Request,
                  mut res: Response<hyper::net::Fresh>)
                  -> Result<(), Error> {
        let path = self.uri_to_path(&req, &mut res)?;
        let mut file = File::create(path)
            .map_err(|e| io_error_to_status(e, &mut res))?;
        io::copy(&mut req, &mut file)?;
        Ok(())
    }

    fn handle_copy(&self, req: Request, mut res: Response<hyper::net::Fresh>) -> Result<(), Error> {
        let (src, dst) = self.uri_to_src_dst(&req, &mut res)?;
        debug!("Copy {:?} -> {:?}", src, dst);

        // TODO: handle overwrite flags and directory copies
        // TODO: proper error for out of space
        fs::copy(src, dst)
            .map_err(|e| io_error_to_status(e, &mut res))?;
        *res.status_mut() == StatusCode::Created;
        Ok(())
    }

    fn handle_move(&self, req: Request, mut res: Response<hyper::net::Fresh>) -> Result<(), Error> {
        let (src, dst) = self.uri_to_src_dst(&req, &mut res)?;
        debug!("Move {:?} -> {:?}", src, dst);

        // TODO: handle overwrite flags
        fs::rename(src, dst)
            .map_err(|e| io_error_to_status(e, &mut res))?;
        *res.status_mut() == StatusCode::Created;
        Ok(())
    }

    fn handle_delete(&self,
                     req: Request,
                     mut res: Response<hyper::net::Fresh>)
                     -> Result<(), Error> {
        // Get the file
        let path = self.uri_to_path(&req, &mut res)?;
        let meta = path.metadata()
            .map_err(|e| io_error_to_status(e, &mut res))?;
        if meta.is_dir() {
                fs::remove_dir_all(path)
            } else {
                fs::remove_file(path)
            }
            .map_err(|e| io_error_to_status(e, &mut res))?;
        Ok(())
    }

    fn handle_mkdir(&self,
                    req: Request,
                    mut res: Response<hyper::net::Fresh>)
                    -> Result<(), Error> {
        let path = self.uri_to_path(&req, &mut res)?;
        let ret = fs::create_dir(path);
        match ret {
            Ok(_) => *res.status_mut() = StatusCode::Created,
            Err(ref e) if e.kind() == ErrorKind::NotFound => {
                *res.status_mut() = StatusCode::Conflict;
            }
            Err(_) => *res.status_mut() = StatusCode::InternalServerError,
        };
        ret.map_err(Into::into)
    }
}

impl Handler for Server {
    fn handle<'a, 'k>(&'a self, req: Request<'a, 'k>, mut res: Response<'a, hyper::net::Fresh>) {
        debug!("Request {:?}", req.method);

        let reqtype = match req.method {
            Method::Options => RequestType::Options,
            Method::Get => RequestType::Get,
            Method::Put => RequestType::Put,
            Method::Delete => RequestType::Delete,
            Method::Extension(ref s) if s == "PROPFIND" => RequestType::Propfind,
            Method::Extension(ref s) if s == "COPY" => RequestType::Copy,
            Method::Extension(ref s) if s == "MOVE" => RequestType::Move,
            Method::Extension(ref s) if s == "MKCOL" => RequestType::Mkdir,
            _ => {
                *res.status_mut() = StatusCode::BadRequest;
                return;
            }
        };

        if let Err(e) = match reqtype {
               RequestType::Options => {
                   res.headers_mut()
                       .set(hyper::header::Allow(vec![Method::Options,
                                                      Method::Get,
                                                      Method::Put,
                                                      Method::Delete,
                                                      Method::Extension("PROPFIND".into()),
                                                      Method::Extension("COPY".into()),
                                                      Method::Extension("MOVE".into()),
                                                      Method::Extension("MKCOL".into())]));
                   res.headers_mut().set_raw("DAV", vec![b"1".to_vec()]);
                   Ok(())
               }
               RequestType::Propfind => self.handle_propfind(req, res),
               RequestType::Get => self.handle_get(req, res),
               RequestType::Put => self.handle_put(req, res),
               RequestType::Copy => self.handle_copy(req, res),
               RequestType::Move => self.handle_move(req, res),
               RequestType::Delete => self.handle_delete(req, res),
               RequestType::Mkdir => self.handle_mkdir(req, res),
           } {
            error!("Request error {:?}", e)
        }
    }
}
