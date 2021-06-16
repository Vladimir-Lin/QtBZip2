/****************************************************************************
 *
 * Copyright (C) 2001~2016 Neutrino International Inc.
 *
 * Author   : Brian Lin ( Vladimir Lin , Vladimir Forest )
 * E-mail   : lin.foxman@gmail.com
 *          : lin.vladimir@gmail.com
 *          : wolfram_lin@yahoo.com
 *          : wolfram_lin@sina.com
 *          : wolfram_lin@163.com
 * Skype    : wolfram_lin
 * WeChat   : 153-0271-7160
 * WhatsApp : 153-0271-7160
 * QQ       : lin.vladimir@gmail.com
 * URL      : http://qtbzip2.sourceforge.net/
 *
 * QtLZO acts as an interface between Qt and LZO library.
 * Please keep QtBZip2 as simple as possible.
 *
 * Copyright 2001 ~ 2016
 *
 ****************************************************************************/

#ifndef QT_BZIP2_H
#define QT_BZIP2_H

#include <QtCore>
#include <QtScript>

QT_BEGIN_NAMESPACE

#ifndef QT_STATIC
#    if defined(QT_BUILD_QTBZIP2_LIB)
#      define Q_BZIP2_EXPORT Q_DECL_EXPORT
#    else
#      define Q_BZIP2_EXPORT  Q_DECL_IMPORT
#    endif
#    define __BZIP2_EXPORT1 Q_DECL_IMPORT
#else
#    define Q_BZIP2_EXPORT
#endif

#define QT_BZIP2_LIB 1

class Q_BZIP2_EXPORT QtBZip2         ;
class Q_BZIP2_EXPORT ScriptableBZip2 ;

class Q_BZIP2_EXPORT QtBZip2
{
  public:

    explicit        QtBZip2         (void) ;
    virtual        ~QtBZip2         (void) ;

    static  QString Version         (void) ;

    virtual bool    isBZip2         (QByteArray & header) ;

    virtual void    CleanUp         (void) ;

    virtual bool    IsCorrect       (int returnCode) ;
    virtual bool    IsEnd           (int returnCode) ;
    virtual bool    IsFault         (int returnCode) ;

    // Compression functions

    virtual int     BeginCompress   (int level = 9,int workFactor = 30) ;
    virtual int     BeginCompress   (QVariantList arguments = QVariantList() ) ;
    virtual int     doCompress      (const QByteArray & Source      ,
                                           QByteArray & Compressed) ;
    virtual int     doSection       (      QByteArray & Source      ,
                                           QByteArray & Compressed) ;
    virtual int     CompressDone    (QByteArray & Compressed) ;

    // Decompression functions

    virtual int     BeginDecompress (void) ;
    virtual int     doDecompress    (const QByteArray & Source        ,
                                           QByteArray & Decompressed) ;
    virtual int     undoSection     (      QByteArray & Source        ,
                                           QByteArray & Decompressed) ;
    virtual int     DecompressDone  (void) ;

    virtual bool    IsTail          (QByteArray & header) ;

  protected:

    QMap < QString , QVariant > DebugInfo ;
    void                      * BzPacket  ;

    virtual bool    CompressHeader  (QByteArray & Compressed) ;
    virtual bool    CompressTail    (QByteArray & Compressed) ;

  private:

} ;

class Q_BZIP2_EXPORT ScriptableBZip2 : public QObject
                                     , public QScriptable
                                     , public QtBZip2
{
  Q_OBJECT
  public:

    static QScriptValue Attachment      (QScriptContext * context,QScriptEngine * engine) ;

    explicit            ScriptableBZip2 (QObject * parent) ;
    virtual            ~ScriptableBZip2 (void) ;

  protected:

  private:

  public slots:

    virtual bool        ToBZip2         (QString file,QString lzo,int level = 9,int workFactor = 30) ;
    virtual bool        ToFile          (QString lzo,QString file) ;

  protected slots:

  private slots:

  signals:

} ;

Q_BZIP2_EXPORT void       BZip2CRC        (const QByteArray & Data              ,
                                           unsigned int     & bcrc            ) ;
Q_BZIP2_EXPORT void       BZip2CRC        (int                length            ,
                                           const QByteArray & Data              ,
                                           unsigned int     & bcrc            ) ;
Q_BZIP2_EXPORT QByteArray BZip2Compress   (const QByteArray & data              ,
                                           int                level = 9       ) ;
Q_BZIP2_EXPORT QByteArray BZip2Uncompress (const QByteArray & data            ) ;
Q_BZIP2_EXPORT bool       ToBZip2         (const QByteArray & data              ,
                                                 QByteArray & bzip2             ,
                                           int                level      = 9    ,
                                           int                workFactor = 30 ) ;
Q_BZIP2_EXPORT bool       FromBZip2       (const QByteArray & bzip2             ,
                                                 QByteArray & data            ) ;
Q_BZIP2_EXPORT bool       SaveBZip2       (QString            filename          ,
                                           QByteArray       & data              ,
                                           int                level      = 9    ,
                                           int                workFactor = 30 ) ;
Q_BZIP2_EXPORT bool       LoadBZip2       (QString            filename          ,
                                           QByteArray       & data            ) ;
Q_BZIP2_EXPORT bool       FileToBZip2     (QString            filename          ,
                                           QString            bzip2             ,
                                           int                level      = 9    ,
                                           int                workFactor = 30 ) ;
Q_BZIP2_EXPORT bool       BZip2ToFile     (QString            bzip2             ,
                                           QString            filename        ) ;


QT_END_NAMESPACE

#endif
