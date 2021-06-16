#include <QtCore>
#include <QtBZip2>

void nprintf(QString message,bool lf,bool cr)
{
  QTextCodec * codec = QTextCodec::codecForLocale() ;
  QByteArray   M     = codec->fromUnicode(message)  ;
  int          L     = M . size ( )                 ;
  ///////////////////////////////////////////////////
  if ( L <= 0 )                                     {
    if (lf || cr)                                   {
      char f [ 64 ]                                 ;
      ::strcpy         ( f    , ""    )             ;
      if (cr) ::strcat ( f    , "\r"  )             ;
      if (lf) ::strcat ( f    , "\n"  )             ;
      ::printf         ( "%s" , f     )             ;
    }                                               ;
    return                                          ;
  }                                                 ;
  ///////////////////////////////////////////////////
  char * p = new char[L+16]                         ;
  memset   ( p , 0        , L+16 )                  ;
  memcpy   ( p , M.data() , L    )                  ;
  if (lf || cr)                                     {
    char f [ 64 ]                                   ;
    ::strcpy         ( f , ""      )                ;
    if (cr) ::strcat ( f , "\r"    )                ;
    if (lf) ::strcat ( f , "\n"    )                ;
    ::strcat         ( p , f       )                ;
  }                                                 ;
  ::printf           ( "%s" , p    )                ;
  delete [] p                                       ;
}

QStringList ToArgs(int argc,char ** argv)
{
  QTextCodec * codec = QTextCodec::codecForLocale ( ) ;
  QStringList  s                                      ;
  for (int i = 0 ; i < argc ; i++ )                   {
    s << codec -> toUnicode ( argv [ i ] )            ;
  }                                                   ;
  return s                                            ;
}

bool LoadAll(QString filename,QByteArray & data)
{
  QFile F ( filename )                                   ;
  if ( ! F . open ( QIODevice::ReadOnly ) ) return false ;
  data = F . readAll ( )                                 ;
  F . close ( )                                          ;
  return true                                            ;
}

bool SaveAll(QString filename,QByteArray & data)
{
  QFile F ( filename )                                   ;
  if ( ! F . open ( QIODevice::WriteOnly                 |
                    QIODevice::Truncate ) ) return false ;
  F . write ( data )                                     ;
  F . close (      )                                     ;
  return true                                            ;
}

bool Compress(QString ifile,QString ofile,int level)
{
  QByteArray data                                                   ;
  if ( ! LoadAll ( ifile , data ) )                                 {
    nprintf ( QString("Can not load %1").arg(ifile) , true , true ) ;
    return false                                                    ;
  }                                                                 ;
  ///////////////////////////////////////////////////////////////////
  if ( data . size ( ) <= 0 )                                       {
    nprintf ( QString("No data in %1").arg(ifile) , true , true )   ;
    return false                                                    ;
  }                                                                 ;
  ///////////////////////////////////////////////////////////////////
  QByteArray bzip2                                                  ;
  if ( ToBZip2 ( data , bzip2 ) && ( bzip2 . size ( ) > 0 ) )       {
    if ( SaveAll ( ofile , bzip2 ) )                                {
      nprintf ( QString ( "Compress %1 bytes into %2 bytes"         )
                . arg   ( data  . size ( )                          )
                . arg   ( bzip2 . size ( )                        ) ,
                true                                                ,
                true                                              ) ;
      return true                                                   ;
    }                                                               ;
  }                                                                 ;
  ///////////////////////////////////////////////////////////////////
  nprintf ( "Compression failure" , true , true )                   ;
  ///////////////////////////////////////////////////////////////////
  return false                                                      ;
}

bool Decompress(QString ifile,QString ofile)
{
  QByteArray bzip2                                                  ;
  if ( ! LoadAll ( ifile , bzip2 ) )                                {
    nprintf ( QString("Can not load %1").arg(ifile) , true , true ) ;
    return false                                                    ;
  }                                                                 ;
  ///////////////////////////////////////////////////////////////////
  if ( bzip2 . size ( ) <= 0 )                                      {
    nprintf ( QString("No data in %1").arg(ifile) , true , true )   ;
    return false                                                    ;
  }                                                                 ;
  ///////////////////////////////////////////////////////////////////
  QByteArray data                                                   ;
  if ( FromBZip2 ( bzip2 , data ) && ( data . size ( ) > 0 ) )      {
    if ( SaveAll ( ofile , data ) )                                 {
      nprintf ( QString ( "Decompress %1 bytes into %2 bytes"       )
                . arg   ( bzip2 . size ( )                          )
                . arg   ( data  . size ( )                        ) ,
                true                                                ,
                true                                              ) ;
      return true                                                   ;
    }                                                               ;
  }                                                                 ;
  ///////////////////////////////////////////////////////////////////
  nprintf ( "Decompression failure" , true , true )                 ;
  ///////////////////////////////////////////////////////////////////
  return false                                                      ;
}

bool JsBZip2(QString ifile,QString entry)
{
  QString    m                                                               ;
  QByteArray SCRIPT                                                          ;
  ////////////////////////////////////////////////////////////////////////////
  if ( ( ! LoadAll ( ifile , SCRIPT ) ) || ( SCRIPT . size ( ) <= 0 ) )      {
    m = QString("<%1> can not be loaded.\r\n").arg(ifile)                    ;
    nprintf ( m , true , true )                                              ;
    return false                                                             ;
  }                                                                          ;
  ////////////////////////////////////////////////////////////////////////////
  QScriptEngine    Engine                                                    ;
  QString          script                                                    ;
  QScriptValue     func                                                      ;
  QScriptValue     global                                                    ;
  QScriptValue     bzip2                                                     ;
  QScriptValue     again                                                     ;
  QScriptValueList args                                                      ;
  ////////////////////////////////////////////////////////////////////////////
  script = QString::fromUtf8     ( SCRIPT                                  ) ;
  func   = Engine . evaluate     ( script                                  ) ;
  global = Engine . globalObject (                                         ) ;
  global . setProperty                                                       (
    "QtBZip2"                                                                ,
    Engine . newFunction ( ScriptableBZip2::Attachment )                   ) ;
  bzip2    = global . property     ( entry                                 ) ;
  ////////////////////////////////////////////////////////////////////////////
  if ( bzip2 . isFunction ( ) )                                              {
    again = bzip2 . call ( func , args  )                                    ;
  } else                                                                     {
    m = QString("<%1> can not be found in <%2>.\r\n").arg(entry).arg(ifile)  ;
    nprintf ( m , true , true )                                              ;
    return false                                                             ;
  }                                                                          ;
  ////////////////////////////////////////////////////////////////////////////
  return true                                                                ;
}

void Help (void)
{
  nprintf("Compress   : bzip2tool -c -i input -o output.bz2 -l level",true,true) ;
  nprintf("Decompress : bzip2tool -e -i input.bz2 -o output"         ,true,true) ;
  nprintf("Javascript : bzip2tool -j -f function -i input.js"        ,true,true) ;
}

int Interpret(QStringList cmds)
{
  if ( cmds . count ( ) < 2 )          {
    Help ( )                           ;
    return 1                           ;
  }                                    ;
  int     ioa = -1                     ;
  //////////////////////////////////////
  cmds . takeAt ( 0 )                  ;
  if ( "-c" == cmds [ 0 ] )            {
    ioa = 1                            ;
  }                                    ;
  if ( "-e" == cmds [ 0 ] )            {
    ioa = 2                            ;
  }                                    ;
  if ( "-j" == cmds [ 0 ] )            {
    ioa = 3                            ;
  }                                    ;
  if ( ( ioa < 1 ) || ( ioa > 3 ) )    {
    Help ( )                           ;
    return 1                           ;
  }                                    ;
  //////////////////////////////////////
  QString ifile = ""                   ;
  QString ofile = ""                   ;
  QString entry = ""                   ;
  int     l     = 9                    ;
  cmds . takeAt ( 0 )                  ;
  while ( cmds . count ( ) > 0 )       {
    if ( "-i" == cmds [ 0 ] )          {
      cmds . takeAt ( 0 )              ;
      if ( cmds . count ( ) > 0 )      {
        ifile = cmds [ 0 ]             ;
        cmds . takeAt ( 0 )            ;
      } else                           {
        Help ( )                       ;
        return 1                       ;
      }                                ;
    } else
    if ( "-o" == cmds [ 0 ] )          {
      cmds . takeAt ( 0 )              ;
      if ( cmds . count ( ) > 0 )      {
        ofile = cmds [ 0 ]             ;
        cmds . takeAt ( 0 )            ;
      } else                           {
        Help ( )                       ;
        return 1                       ;
      }                                ;
    } else
    if ( "-l" == cmds [ 0 ] )          {
      cmds . takeAt ( 0 )              ;
      if ( cmds . count ( ) > 0 )      {
        l = cmds [ 0 ] . toInt ( )     ;
        cmds . takeAt ( 0 )            ;
      } else                           {
        Help ( )                       ;
        return 1                       ;
      }                                ;
    } else
    if ( "-f" == cmds [ 0 ] )          {
      cmds . takeAt ( 0 )              ;
      if ( cmds . count ( ) > 0 )      {
        entry = cmds [ 0 ]             ;
        cmds . takeAt ( 0 )            ;
      } else                           {
        Help ( )                       ;
        return 1                       ;
      }                                ;
    } else
    if ( cmds . count ( ) > 0 )        {
      cmds . takeAt ( 0 )              ;
    }                                  ;
  }                                    ;
  //////////////////////////////////////
  switch ( ioa )                       {
    case 1                             :
    case 2                             :
      if ( ( ifile.length ( ) <= 0 )  ||
           ( ofile.length ( ) <= 0 ) ) {
        Help ( )                       ;
        return 1                       ;
      }                                ;
    break                              ;
    case 3                             :
      if ( ( ifile.length ( ) <= 0 )  ||
           ( entry.length ( ) <= 0 ) ) {
        Help ( )                       ;
        return 1                       ;
      }                                ;
    break                              ;
  }                                    ;
  //////////////////////////////////////
  switch ( ioa )                       {
    case 1                             :
      Compress   ( ifile , ofile , l ) ;
    return 0                           ;
    case 2                             :
      Decompress ( ifile , ofile     ) ;
    return 0                           ;
    case 3                             :
      JsBZip2    ( ifile , entry     ) ;
    return 0                           ;
  }                                    ;
  //////////////////////////////////////
  Help ( )                             ;
  return 1                             ;
}

int main(int argc,char ** argv)
{
  QStringList      args = ToArgs ( argc , argv ) ;
  QCoreApplication core          ( argc , argv ) ;
  return Interpret               ( args        ) ;
}
