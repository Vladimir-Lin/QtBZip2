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
 * QtBZip2 acts as an interface between Qt and BZip2 library.
 * Please keep QtBZip2 as simple as possible.
 *
 * Copyright 2001 ~ 2016
 *
 ****************************************************************************/

#include <qtbzip2.h>

QT_BEGIN_NAMESPACE

ScriptableBZip2:: ScriptableBZip2 ( QObject * parent )
                : QObject         (           parent )
                , QScriptable     (                  )
                , QtBZip2         (                  )
{
}

ScriptableBZip2::~ScriptableBZip2 (void)
{
}

bool ScriptableBZip2::ToBZip2(QString file,QString bzip2,int level,int workFactor)
{
  return FileToBZip2 ( file , bzip2 , level , workFactor ) ;
}

bool ScriptableBZip2::ToFile(QString bzip2,QString file)
{
  return BZip2ToFile ( bzip2 , file ) ;
}

QScriptValue ScriptableBZip2::Attachment(QScriptContext * context,QScriptEngine * engine)
{
  ScriptableBZip2 * bzip2 = new ScriptableBZip2 ( engine ) ;
  return engine -> newQObject                   ( bzip2  ) ;
}

QT_END_NAMESPACE
