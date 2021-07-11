/****************************************************************************
 *
 * Copyright (C) 2001 ~ 2021
 * 
 *  Neutrino International Inc.
 *  Oriphase Space Travelling Industry
 *
 * Author   : Brian Lin ( Foxman , Vladimir Lin , Vladimir Forest )
 * E-mail   : lin.foxman@gmail.com
 *          : lin.vladimir@gmail.com
 *          : wolfram_lin@yahoo.com
 *          : wolfram_lin@sina.com
 *          : wolfram_lin@163.com
 * Skype    : wolfram_lin
 * WeChat   : 153-0271-7160
 * WhatsApp : 153-0271-7160
 * QQ       : lin.vladimir@gmail.com (2107437784)
 * LINE     : lin-foxman
 *
 ****************************************************************************/

#include "qtbzip2.h"

QT_BEGIN_NAMESPACE

#ifndef QT_STATIC

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

#endif

QT_END_NAMESPACE
