function Fetch(url,filename,timeout)
{
  var msg                                            ;
  var r                                              ;
  mt  = new MtJS ( )                                 ;
  ftp = new FTP  ( )                                 ;
  msg = "下載 " + url + " 到 " + filename             ;
  mt  . toConsoleLn ( msg                          ) ;
  r = ftp . Download    ( url , filename , timeout ) ;
  delete ftp                                         ;
  delete mt                                          ;
  return r                                           ;
}

function Download()
{
  var url      = "http://www.oberhumer.com/opensource/lzo/download/" ;
  var filename = "G:/Temp/oberhumer.html"                            ;
  var timeout  = 60 * 1000                                           ;
  return Fetch ( url , filename , timeout )                          ;
}

function CheckBZip2()
{
  var version = "lzo-2.10.tar.gz"               ;
  var msg                                       ;
  var lzs                                       ;
  var obs                                       ;
  lzob = new ByteArray ( )                      ;
  ober = new ByteArray ( )                      ;
  if ( ! Download ( ) )                         {
    return                                      ;
  }                                             ;
  lzob . Load ( "G:/Temp/lzo-download.html" )   ;
  ober . Load ( "G:/Temp/oberhumer.html"    )   ;
  lzs = lzob . Size ( )                         ;
  obs = ober . Size ( )                         ;
  if ( lzs !== obs )                            {
    ober . Save ( "G:/Temp/lzo-download.html" ) ;
    if ( ober . Contains ( version ) )          {
      msg = "New version : " + version          ;
      print ( msg )                             ;
    }                                           ;
  }                                             ;
  delete lzob                                   ;
  delete ober                                   ;
}
