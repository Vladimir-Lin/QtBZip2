function CompressBZip2()
{
  bzip2 = new QtBZip2 ( ) ;
  bzip2 . ToBZip2 ( "Testing.txt" , "Testing.lzo" , 9 , 30 ) ;
  delete bzip2 ;
}

function DecompressBZip2()
{
  bzip2 = new QtBZip2 ( ) ;
  bzip2 . ToFile ( "Testing.lzo" , "Testing.txt" ) ;
  delete bzip2 ;
}
