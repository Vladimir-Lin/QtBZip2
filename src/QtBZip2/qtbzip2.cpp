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

/*****************************************************************************\
 *                                                                           *
 *                                BZip2 File Header                          *
 *                                                                           *
 * .magic:16                       = 'BZ' signature/magic number
 * .version:8                      = 'h' for Bzip2 ('H'uffman coding), '0' for Bzip1 (deprecated)
 * .hundred_k_blocksize:8          = '1'..'9' block-size 100 kB-900 kB (uncompressed)
 *
 * .compressed_magic:48            = 0x314159265359 (BCD (pi))
 * .crc:32                         = checksum for this block
 * .randomised:1                   = 0=>normal, 1=>randomised (deprecated)
 * .origPtr:24                     = starting pointer into BWT for after untransform
 * .huffman_used_map:16            = bitmap, of ranges of 16 bytes, present/not present
 * .huffman_used_bitmaps:0..256    = bitmap, of symbols used, present/not present (multiples of 16)
 * .huffman_groups:3               = 2..6 number of different Huffman tables in use
 * .selectors_used:15              = number of times that the Huffman tables are swapped (each 50 bytes)
 * *.selector_list:1..6            = zero-terminated bit runs (0..62) of MTF'ed Huffman table (*selectors_used)
 * .start_huffman_length:5         = 0..20 starting bit length for Huffman deltas
 * *.delta_bit_length:1..40        = 0=>next symbol; 1=>alter length
                                                { 1=>decrement length;  0=>increment length } (*(symbols+2)*groups)
 * .contents:2..∞                  = Huffman encoded data stream until end of block
 *                                                                           *
 * .eos_magic:48                   = 0x177245385090 (BCD sqrt(pi))
 * .crc:32                         = checksum for whole stream
 * .padding:0..7                   = align to whole byte
 *                                                                           *
 *                                                                           *
\*****************************************************************************/

#define IsNull(item)         (NULL==(item))
#define NotNull(item)        (NULL!=(item))
#define NotEqual(a,b)        ((a)!=(b))

#define BZ_RUN               0
#define BZ_FLUSH             1
#define BZ_FINISH            2

#define BZ_OK                0
#define BZ_RUN_OK            1
#define BZ_FLUSH_OK          2
#define BZ_FINISH_OK         3
#define BZ_STREAM_END        4
#define BZ_SEQUENCE_ERROR    (-1)
#define BZ_PARAM_ERROR       (-2)
#define BZ_MEM_ERROR         (-3)
#define BZ_DATA_ERROR        (-4)
#define BZ_DATA_ERROR_MAGIC  (-5)
#define BZ_IO_ERROR          (-6)
#define BZ_UNEXPECTED_EOF    (-7)
#define BZ_OUTBUFF_FULL      (-8)
#define BZ_CONFIG_ERROR      (-9)

#define BZ_N_GROUPS          6
#define BZ_N_ITERS           4
#define BZ_N_RADIX           2
#define BZ_N_QSORT           12
#define BZ_N_SHELL           18
#define BZ_N_OVERSHOOT       (BZ_N_RADIX + BZ_N_QSORT + BZ_N_SHELL + 2)

#define BZ_G_SIZE            50

#define BZ_M_IDLE            1
#define BZ_M_RUNNING         2
#define BZ_M_FLUSHING        3
#define BZ_M_FINISHING       4

#define BZ_S_OUTPUT          1
#define BZ_S_INPUT           2

#define BZ_HDR_B             0x42 /* 'B' */
#define BZ_HDR_Z             0x5a /* 'Z' */
#define BZ_HDR_h             0x68 /* 'h' */
#define BZ_HDR_0             0x30 /* '0' */

#define BZ_RUNA              0
#define BZ_RUNB              1

#define BZ_MAX_UNUSED        8192
#define BZ_MAX_ALPHA_SIZE    258
#define BZ_MAX_CODE_LEN      23
#define BZ_MAX_SELECTORS     (2 + (900000 / BZ_G_SIZE))

#define BZ_X_IDLE            1
#define BZ_X_OUTPUT          2
#define BZ_X_MAGIC_1         10
#define BZ_X_MAGIC_2         11
#define BZ_X_MAGIC_3         12
#define BZ_X_MAGIC_4         13
#define BZ_X_BLKHDR_1        14
#define BZ_X_BLKHDR_2        15
#define BZ_X_BLKHDR_3        16
#define BZ_X_BLKHDR_4        17
#define BZ_X_BLKHDR_5        18
#define BZ_X_BLKHDR_6        19
#define BZ_X_BCRC_1          20
#define BZ_X_BCRC_2          21
#define BZ_X_BCRC_3          22
#define BZ_X_BCRC_4          23
#define BZ_X_RANDBIT         24
#define BZ_X_ORIGPTR_1       25
#define BZ_X_ORIGPTR_2       26
#define BZ_X_ORIGPTR_3       27
#define BZ_X_MAPPING_1       28
#define BZ_X_MAPPING_2       29
#define BZ_X_SELECTOR_1      30
#define BZ_X_SELECTOR_2      31
#define BZ_X_SELECTOR_3      32
#define BZ_X_CODING_1        33
#define BZ_X_CODING_2        34
#define BZ_X_CODING_3        35
#define BZ_X_MTF_1           36
#define BZ_X_MTF_2           37
#define BZ_X_MTF_3           38
#define BZ_X_MTF_4           39
#define BZ_X_MTF_5           40
#define BZ_X_MTF_6           41
#define BZ_X_ENDHDR_2        42
#define BZ_X_ENDHDR_3        43
#define BZ_X_ENDHDR_4        44
#define BZ_X_ENDHDR_5        45
#define BZ_X_ENDHDR_6        46
#define BZ_X_CCRC_1          47
#define BZ_X_CCRC_2          48
#define BZ_X_CCRC_3          49
#define BZ_X_CCRC_4          50

#define MTFA_SIZE            4096
#define MTFL_SIZE            16

#define BZALLOC(nnn) (strm->bzalloc)(strm->opaque,(nnn),1)
#define BZFREE(ppp)  (strm->bzfree)(strm->opaque,(ppp))

#define BZ_RAND_INIT_MASK \
   s->rNToGo = 0;         \
   s->rTPos  = 0          \

#define BZ_RAND_MASK ((s->rNToGo == 1) ? 1 : 0)

#define BZ_RAND_UPD_MASK                  \
   if (s->rNToGo == 0)                  { \
      s->rNToGo = Bz2rNums[s->rTPos]    ; \
      s->rTPos++                        ; \
      if (s->rTPos == 512) s->rTPos = 0 ; \
   }                                      \
   s->rNToGo--                            ;

#define BZ_GET_FAST(cccc)                                  \
    if (s->tPos >= ( (unsigned int)100000 * (unsigned int)s->blockSize100k ) ) return true; \
    s->tPos = s->tt[s->tPos];                              \
    cccc = (unsigned char)(s->tPos & 0xff);                \
    s->tPos >>= 8                                          ;

#define BZ_GET_FAST_C(cccc)                                \
    if (c_tPos >= ( (unsigned int)100000 * (unsigned int)ro_blockSize100k ) ) return true; \
    c_tPos = c_tt[c_tPos];                                 \
    cccc = (unsigned char)(c_tPos & 0xff);                 \
    c_tPos >>= 8                                           ;

#define SET_LL4(i,n)                                              \
   { if (((i) & 0x1) == 0)                                        \
       s->ll4[(i) >> 1] = (s->ll4[(i) >> 1] & 0xf0) | (n); else   \
       s->ll4[(i) >> 1] = (s->ll4[(i) >> 1] & 0x0f) | ((n) << 4); \
   }

#define GET_LL4(i)                             \
   ((((unsigned int)(s->ll4[(i) >> 1])) >> (((i) << 2) & 0x4)) & 0xF)

#define SET_LL(i,n)                                 \
   { s->ll16[i] = (unsigned short)(n & 0x0000ffff); \
     SET_LL4(i, n >> 16);                           \
   }

#define GET_LL(i) (((unsigned int)s->ll16[i]) | (GET_LL4(i) << 16))

#define BZ_GET_SMALL(cccc)                                 \
    /* c_tPos is unsigned, hence test < 0 is pointless. */ \
    if (s->tPos >= (unsigned int)100000 * (unsigned int)s->blockSize100k) return true; \
    cccc = indexIntoF ( s->tPos, s->cftab );               \
    s->tPos = GET_LL(s->tPos)                              ;

#define RETURN(rrr) { retVal = rrr; goto save_state_and_return; }

#define GET_BITS(lll,vvv,nnn)                     \
   case lll: s->state = lll;                      \
   while ( true )                               { \
      if (s->bsLive >= nnn)                     { \
        unsigned int v                          ; \
         v = (s->bsBuff >>                        \
             (s->bsLive-nnn)) & ((1 << nnn)-1);   \
         s->bsLive -= nnn;                        \
         vvv = v;                                 \
         break;                                   \
      }                                           \
      if (s->strm->avail_in == 0) RETURN(BZ_OK);  \
      s->bsBuff                                   \
         = (s->bsBuff << 8) |                     \
           ((unsigned int)                        \
              (*((unsigned char*)(s->strm->next_in)))); \
      s->bsLive += 8;                             \
      s->strm->next_in++;                         \
      s->strm->avail_in--;                        \
      s->strm->total_in_lo32++;                   \
      if (s->strm->total_in_lo32 == 0)            \
         s->strm->total_in_hi32++;                \
   }

#define GET_UCHAR(lll,uuu) GET_BITS(lll,uuu,8)

#define GET_BIT(lll,uuu) GET_BITS(lll,uuu,1)

#define GET_MTF_VAL(label1,label2,lval)           \
{                                                 \
   if (groupPos == 0) {                           \
      groupNo++;                                  \
      if (groupNo >= nSelectors)                  \
         RETURN(BZ_DATA_ERROR);                   \
      groupPos = BZ_G_SIZE;                       \
      gSel     =   s->selector[ groupNo ]  ;      \
      gMinlen  =   s->minLens [ gSel    ]  ;      \
      gLimit   = &(s->limit   [gSel ] [0]) ;      \
      gPerm    = &(s->perm    [gSel ] [0]) ;      \
      gBase    = &(s->base    [gSel ] [0]) ;      \
   }                                              \
   groupPos--;                                    \
   zn = gMinlen;                                  \
   GET_BITS(label1, zvec, zn);                    \
   while ( true    )                            { \
      if ( zn > 20 )                              \
         RETURN(BZ_DATA_ERROR);                   \
      if (zvec <= gLimit[zn]) break;              \
      zn++;                                       \
      GET_BIT(label2, zj);                        \
      zvec = (zvec << 1) | zj;                    \
   };                                             \
   if (zvec - gBase[zn] < 0                       \
       || zvec - gBase[zn] >= BZ_MAX_ALPHA_SIZE)  \
      RETURN(BZ_DATA_ERROR);                      \
   lval = gPerm[zvec - gBase[zn]];                \
}

#define BZ_INITIALISE_CRC(crcVar)          \
{                                          \
   crcVar = 0xffffffffL;                   \
}

#define BZ_FINALISE_CRC(crcVar)            \
{                                          \
   crcVar = ~(crcVar);                     \
}

#define BZ_UPDATE_CRC(crcVar,cha)          \
{                                          \
   crcVar = (crcVar << 8)                ^ \
            Bz2crc32Table[(crcVar >> 24) ^ \
                   ((unsigned char)cha)] ; \
}

///////////////////////////////////////////////////////////////////////////////

#pragma pack(push,1)

struct BzStreaming                         {
  char        * next_in                    ;
  unsigned int  avail_in                   ;
  unsigned int  total_in_lo32              ;
  unsigned int  total_in_hi32              ;
  char        * next_out                   ;
  unsigned int  avail_out                  ;
  unsigned int  total_out_lo32             ;
  unsigned int  total_out_hi32             ;
  void        * state                      ;
  void        * (*bzalloc)(void *,int,int) ;
  void          (*bzfree )(void *,void * ) ;
  void        * opaque                     ;
}                                          ;

typedef struct BzStreaming BzStream        ;

struct BzEncodeState                                            {
  BzStream       * strm                                         ;
  int              mode                                         ;
  int              state                                        ;
  unsigned int     avail_in_expect                              ;
  unsigned int   * arr1                                         ;
  unsigned int   * arr2                                         ;
  unsigned int   * ftab                                         ;
  int              origPtr                                      ;
  unsigned int   * ptr                                          ;
  unsigned char  * block                                        ;
  unsigned short * mtfv                                         ;
  unsigned char  * zbits                                        ;
  int              workFactor                                   ;
  unsigned int     state_in_ch                                  ;
  int              state_in_len                                 ;
  int              rNToGo                                       ;
  int              rTPos                                        ;
  int              nblock                                       ;
  int              nblockMAX                                    ;
  int              numZ                                         ;
  int              state_out_pos                                ;
  int              nInUse                                       ;
  bool             inUse      [256]                             ;
  unsigned char    unseqToSeq [256]                             ;
  unsigned int     bsBuff                                       ;
  int              bsLive                                       ;
  unsigned int     blockCRC                                     ;
  unsigned int     combinedCRC                                  ;
  int              verbosity                                    ;
  int              blockNo                                      ;
  int              blockSize100k                                ;
  int              nMTF                                         ;
  int              mtfFreq     [BZ_MAX_ALPHA_SIZE]              ;
  unsigned char    selector    [BZ_MAX_SELECTORS ]              ;
  unsigned char    selectorMtf [BZ_MAX_SELECTORS ]              ;
  unsigned char    len         [BZ_N_GROUPS][BZ_MAX_ALPHA_SIZE] ;
  int              code        [BZ_N_GROUPS][BZ_MAX_ALPHA_SIZE] ;
  int              rfreq       [BZ_N_GROUPS][BZ_MAX_ALPHA_SIZE] ;
  unsigned int     len_pack    [BZ_MAX_ALPHA_SIZE][4]           ;
}                                                               ;

struct BzDecodeState                                            {
  BzStream       * strm                                         ;
  int              state                                        ;
  unsigned char    state_out_ch                                 ;
  int              state_out_len                                ;
  bool             blockRandomised                              ;
  int              rNToGo                                       ;
  int              rTPos                                        ;
  unsigned int     bsBuff                                       ;
  int              bsLive                                       ;
  int              blockSize100k                                ;
  bool             smallDecompress                              ;
  int              currBlockNo                                  ;
  int              verbosity                                    ;
  int              origPtr                                      ;
  unsigned int     tPos                                         ;
  int              k0                                           ;
  int              unzftab   [256]                              ;
  int              nblock_used                                  ;
  int              cftab     [257]                              ;
  int              cftabCopy [257]                              ;
  unsigned int   * tt                                           ;
  unsigned short * ll16                                         ;
  unsigned char  * ll4                                          ;
  unsigned int     storedBlockCRC                               ;
  unsigned int     storedCombinedCRC                            ;
  unsigned int     calculatedBlockCRC                           ;
  unsigned int     calculatedCombinedCRC                        ;
  int              nInUse                                       ;
  bool             inUse       [ 256             ]              ;
  bool             inUse16     [ 16              ]              ;
  unsigned char    seqToUnseq  [ 256             ]              ;
  unsigned char    mtfa        [ MTFA_SIZE       ]              ;
  int              mtfbase     [ 256 / MTFL_SIZE ]              ;
  unsigned char    selector    [BZ_MAX_SELECTORS ]              ;
  unsigned char    selectorMtf [BZ_MAX_SELECTORS ]              ;
  unsigned char    len         [BZ_N_GROUPS][BZ_MAX_ALPHA_SIZE] ;
  int              limit       [BZ_N_GROUPS][BZ_MAX_ALPHA_SIZE] ;
  int              base        [BZ_N_GROUPS][BZ_MAX_ALPHA_SIZE] ;
  int              perm        [BZ_N_GROUPS][BZ_MAX_ALPHA_SIZE] ;
  int              minLens     [BZ_N_GROUPS]                    ;
  int              save_i                                       ;
  int              save_j                                       ;
  int              save_t                                       ;
  int              save_alphaSize                               ;
  int              save_nGroups                                 ;
  int              save_nSelectors                              ;
  int              save_EOB                                     ;
  int              save_groupNo                                 ;
  int              save_groupPos                                ;
  int              save_nextSym                                 ;
  int              save_nblockMAX                               ;
  int              save_nblock                                  ;
  int              save_es                                      ;
  int              save_N                                       ;
  int              save_curr                                    ;
  int              save_zt                                      ;
  int              save_zn                                      ;
  int              save_zvec                                    ;
  int              save_zj                                      ;
  int              save_gSel                                    ;
  int              save_gMinlen                                 ;
  int            * save_gLimit                                  ;
  int            * save_gBase                                   ;
  int            * save_gPerm                                   ;
}                                                               ;

typedef struct BzEncodeState EState                             ;
typedef struct BzDecodeState DState                             ;

typedef struct                        {
  char         buffer [BZ_MAX_UNUSED] ;
  char         unused [BZ_MAX_UNUSED] ;
  int          bufferSize             ;
  bool         Writing                ;
  BzStream     Strm                   ;
  int          LastError              ;
  bool         InitialisedOk          ;
  unsigned int CRC32                  ;
} BzFile                              ;

#pragma pack(pop)

///////////////////////////////////////////////////////////////////////////////

static int
Bz2rNums[512] =                                    {
   619, 720, 127, 481, 931, 816, 813, 233, 566, 247,
   985, 724, 205, 454, 863, 491, 741, 242, 949, 214,
   733, 859, 335, 708, 621, 574,  73, 654, 730, 472,
   419, 436, 278, 496, 867, 210, 399, 680, 480,  51,
   878, 465, 811, 169, 869, 675, 611, 697, 867, 561,
   862, 687, 507, 283, 482, 129, 807, 591, 733, 623,
   150, 238,  59, 379, 684, 877, 625, 169, 643, 105,
   170, 607, 520, 932, 727, 476, 693, 425, 174, 647,
    73, 122, 335, 530, 442, 853, 695, 249, 445, 515,
   909, 545, 703, 919, 874, 474, 882, 500, 594, 612,
   641, 801, 220, 162, 819, 984, 589, 513, 495, 799,
   161, 604, 958, 533, 221, 400, 386, 867, 600, 782,
   382, 596, 414, 171, 516, 375, 682, 485, 911, 276,
    98, 553, 163, 354, 666, 933, 424, 341, 533, 870,
   227, 730, 475, 186, 263, 647, 537, 686, 600, 224,
   469,  68, 770, 919, 190, 373, 294, 822, 808, 206,
   184, 943, 795, 384, 383, 461, 404, 758, 839, 887,
   715,  67, 618, 276, 204, 918, 873, 777, 604, 560,
   951, 160, 578, 722,  79, 804,  96, 409, 713, 940,
   652, 934, 970, 447, 318, 353, 859, 672, 112, 785,
   645, 863, 803, 350, 139,  93, 354,  99, 820, 908,
   609, 772, 154, 274, 580, 184,  79, 626, 630, 742,
   653, 282, 762, 623, 680,  81, 927, 626, 789, 125,
   411, 521, 938, 300, 821,  78, 343, 175, 128, 250,
   170, 774, 972, 275, 999, 639, 495,  78, 352, 126,
   857, 956, 358, 619, 580, 124, 737, 594, 701, 612,
   669, 112, 134, 694, 363, 992, 809, 743, 168, 974,
   944, 375, 748,  52, 600, 747, 642, 182, 862,  81,
   344, 805, 988, 739, 511, 655, 814, 334, 249, 515,
   897, 955, 664, 981, 649, 113, 974, 459, 893, 228,
   433, 837, 553, 268, 926, 240, 102, 654, 459,  51,
   686, 754, 806, 760, 493, 403, 415, 394, 687, 700,
   946, 670, 656, 610, 738, 392, 760, 799, 887, 653,
   978, 321, 576, 617, 626, 502, 894, 679, 243, 440,
   680, 879, 194, 572, 640, 724, 926,  56, 204, 700,
   707, 151, 457, 449, 797, 195, 791, 558, 945, 679,
   297,  59,  87, 824, 713, 663, 412, 693, 342, 606,
   134, 108, 571, 364, 631, 212, 174, 643, 304, 329,
   343,  97, 430, 751, 497, 314, 983, 374, 822, 928,
   140, 206,  73, 263, 980, 736, 876, 478, 430, 305,
   170, 514, 364, 692, 829,  82, 855, 953, 676, 246,
   369, 970, 294, 750, 807, 827, 150, 790, 288, 923,
   804, 378, 215, 828, 592, 281, 565, 555, 710,  82,
   896, 831, 547, 261, 524, 462, 293, 465, 502,  56,
   661, 821, 976, 991, 658, 869, 905, 758, 745, 193,
   768, 550, 608, 933, 378, 286, 215, 979, 792, 961,
    61, 688, 793, 644, 986, 403, 106, 366, 905, 644,
   372, 567, 466, 434, 645, 210, 389, 550, 919, 135,
   780, 773, 635, 389, 707, 100, 626, 958, 165, 504,
   920, 176, 193, 713, 857, 265, 203,  50, 668, 108,
   645, 990, 626, 197, 510, 357, 358, 850, 858, 364,
   936, 638
}                                                  ;

static unsigned int
Bz2crc32Table[256] =                                 {
   0x00000000L, 0x04c11db7L, 0x09823b6eL, 0x0d4326d9L,
   0x130476dcL, 0x17c56b6bL, 0x1a864db2L, 0x1e475005L,
   0x2608edb8L, 0x22c9f00fL, 0x2f8ad6d6L, 0x2b4bcb61L,
   0x350c9b64L, 0x31cd86d3L, 0x3c8ea00aL, 0x384fbdbdL,
   0x4c11db70L, 0x48d0c6c7L, 0x4593e01eL, 0x4152fda9L,
   0x5f15adacL, 0x5bd4b01bL, 0x569796c2L, 0x52568b75L,
   0x6a1936c8L, 0x6ed82b7fL, 0x639b0da6L, 0x675a1011L,
   0x791d4014L, 0x7ddc5da3L, 0x709f7b7aL, 0x745e66cdL,
   0x9823b6e0L, 0x9ce2ab57L, 0x91a18d8eL, 0x95609039L,
   0x8b27c03cL, 0x8fe6dd8bL, 0x82a5fb52L, 0x8664e6e5L,
   0xbe2b5b58L, 0xbaea46efL, 0xb7a96036L, 0xb3687d81L,
   0xad2f2d84L, 0xa9ee3033L, 0xa4ad16eaL, 0xa06c0b5dL,
   0xd4326d90L, 0xd0f37027L, 0xddb056feL, 0xd9714b49L,
   0xc7361b4cL, 0xc3f706fbL, 0xceb42022L, 0xca753d95L,
   0xf23a8028L, 0xf6fb9d9fL, 0xfbb8bb46L, 0xff79a6f1L,
   0xe13ef6f4L, 0xe5ffeb43L, 0xe8bccd9aL, 0xec7dd02dL,
   0x34867077L, 0x30476dc0L, 0x3d044b19L, 0x39c556aeL,
   0x278206abL, 0x23431b1cL, 0x2e003dc5L, 0x2ac12072L,
   0x128e9dcfL, 0x164f8078L, 0x1b0ca6a1L, 0x1fcdbb16L,
   0x018aeb13L, 0x054bf6a4L, 0x0808d07dL, 0x0cc9cdcaL,
   0x7897ab07L, 0x7c56b6b0L, 0x71159069L, 0x75d48ddeL,
   0x6b93dddbL, 0x6f52c06cL, 0x6211e6b5L, 0x66d0fb02L,
   0x5e9f46bfL, 0x5a5e5b08L, 0x571d7dd1L, 0x53dc6066L,
   0x4d9b3063L, 0x495a2dd4L, 0x44190b0dL, 0x40d816baL,
   0xaca5c697L, 0xa864db20L, 0xa527fdf9L, 0xa1e6e04eL,
   0xbfa1b04bL, 0xbb60adfcL, 0xb6238b25L, 0xb2e29692L,
   0x8aad2b2fL, 0x8e6c3698L, 0x832f1041L, 0x87ee0df6L,
   0x99a95df3L, 0x9d684044L, 0x902b669dL, 0x94ea7b2aL,
   0xe0b41de7L, 0xe4750050L, 0xe9362689L, 0xedf73b3eL,
   0xf3b06b3bL, 0xf771768cL, 0xfa325055L, 0xfef34de2L,
   0xc6bcf05fL, 0xc27dede8L, 0xcf3ecb31L, 0xcbffd686L,
   0xd5b88683L, 0xd1799b34L, 0xdc3abdedL, 0xd8fba05aL,
   0x690ce0eeL, 0x6dcdfd59L, 0x608edb80L, 0x644fc637L,
   0x7a089632L, 0x7ec98b85L, 0x738aad5cL, 0x774bb0ebL,
   0x4f040d56L, 0x4bc510e1L, 0x46863638L, 0x42472b8fL,
   0x5c007b8aL, 0x58c1663dL, 0x558240e4L, 0x51435d53L,
   0x251d3b9eL, 0x21dc2629L, 0x2c9f00f0L, 0x285e1d47L,
   0x36194d42L, 0x32d850f5L, 0x3f9b762cL, 0x3b5a6b9bL,
   0x0315d626L, 0x07d4cb91L, 0x0a97ed48L, 0x0e56f0ffL,
   0x1011a0faL, 0x14d0bd4dL, 0x19939b94L, 0x1d528623L,
   0xf12f560eL, 0xf5ee4bb9L, 0xf8ad6d60L, 0xfc6c70d7L,
   0xe22b20d2L, 0xe6ea3d65L, 0xeba91bbcL, 0xef68060bL,
   0xd727bbb6L, 0xd3e6a601L, 0xdea580d8L, 0xda649d6fL,
   0xc423cd6aL, 0xc0e2d0ddL, 0xcda1f604L, 0xc960ebb3L,
   0xbd3e8d7eL, 0xb9ff90c9L, 0xb4bcb610L, 0xb07daba7L,
   0xae3afba2L, 0xaafbe615L, 0xa7b8c0ccL, 0xa379dd7bL,
   0x9b3660c6L, 0x9ff77d71L, 0x92b45ba8L, 0x9675461fL,
   0x8832161aL, 0x8cf30badL, 0x81b02d74L, 0x857130c3L,
   0x5d8a9099L, 0x594b8d2eL, 0x5408abf7L, 0x50c9b640L,
   0x4e8ee645L, 0x4a4ffbf2L, 0x470cdd2bL, 0x43cdc09cL,
   0x7b827d21L, 0x7f436096L, 0x7200464fL, 0x76c15bf8L,
   0x68860bfdL, 0x6c47164aL, 0x61043093L, 0x65c52d24L,
   0x119b4be9L, 0x155a565eL, 0x18197087L, 0x1cd86d30L,
   0x029f3d35L, 0x065e2082L, 0x0b1d065bL, 0x0fdc1becL,
   0x3793a651L, 0x3352bbe6L, 0x3e119d3fL, 0x3ad08088L,
   0x2497d08dL, 0x2056cd3aL, 0x2d15ebe3L, 0x29d4f654L,
   0xc5a92679L, 0xc1683bceL, 0xcc2b1d17L, 0xc8ea00a0L,
   0xd6ad50a5L, 0xd26c4d12L, 0xdf2f6bcbL, 0xdbee767cL,
   0xe3a1cbc1L, 0xe760d676L, 0xea23f0afL, 0xeee2ed18L,
   0xf0a5bd1dL, 0xf464a0aaL, 0xf9278673L, 0xfde69bc4L,
   0x89b8fd09L, 0x8d79e0beL, 0x803ac667L, 0x84fbdbd0L,
   0x9abc8bd5L, 0x9e7d9662L, 0x933eb0bbL, 0x97ffad0cL,
   0xafb010b1L, 0xab710d06L, 0xa6322bdfL, 0xa2f33668L,
   0xbcb4666dL, 0xb8757bdaL, 0xb5365d03L, 0xb1f740b4L
}                                                    ;

///////////////////////////////////////////////////////////////////////////////

static inline void fallbackSimpleSort      (
                     unsigned int * fmap   ,
                     unsigned int * eclass ,
                     int            lo     ,
                     int            hi     )
{
  unsigned int ec_tmp                          ;
  int          i                               ;
  int          j                               ;
  int          tmp                             ;
  //////////////////////////////////////////////
  if (lo == hi) return                         ;
  //////////////////////////////////////////////
  if ( ( hi - lo ) > 3)                        {
    for ( i = hi-4 ; i >= lo ; i-- )           {
      tmp    = fmap   [ i   ]                  ;
      ec_tmp = eclass [ tmp ]                  ;
      for (j = i+4                             ;
           j <= hi && ec_tmp > eclass[fmap[j]] ;
           j += 4                            ) {
        fmap[j-4] = fmap[j]                    ;
      }                                        ;
      fmap[j-4] = tmp                          ;
    }                                          ;
  }                                            ;
  //////////////////////////////////////////////
  for ( i = hi-1; i >= lo; i-- )               {
    tmp    = fmap   [ i   ]                    ;
    ec_tmp = eclass [ tmp ]                    ;
    for (j = i+1                               ;
         j <= hi && ec_tmp > eclass[fmap[j]]   ;
         j++                                 ) {
      fmap[j-1] = fmap[j]                      ;
    }                                          ;
    fmap[j-1] = tmp                            ;
  }                                            ;
}

static void fallbackQSort3          (
              unsigned int * fmap   ,
              unsigned int * eclass ,
              int            loSt   ,
              int            hiSt   )
{
  #define FALLBACK_QSORT_SMALL_THRESH 10
  #define FALLBACK_QSORT_STACK_SIZE   100
  #define fmin(a,b) ((a) < (b)) ? (a) : (b)
  #define fpush(lz,hz)    { stackLo[sp] = lz; stackHi[sp] = hz; sp++; }
  #define fpop(lz,hz)     { sp--; lz = stackLo[sp]; hz = stackHi[sp]; }
  #define fswap(zz1, zz2) { int zztmp = zz1; zz1 = zz2; zz2 = zztmp ; }
  #define fvswap(zzp1, zzp2, zzn)     \
  {                                   \
    int yyp1 = (zzp1);                \
    int yyp2 = (zzp2);                \
    int yyn  = (zzn);                 \
    while (yyn > 0)                 { \
      fswap(fmap[yyp1], fmap[yyp2]) ; \
      yyp1++; yyp2++; yyn--         ; \
    }                                 \
  }
  ///////////////////////////////////////////////////////////////
  int          unLo , unHi , ltLo , gtHi , n , m , sp , lo , hi ;
  unsigned int med  , r    , r3                                 ;
  int          stackLo [ FALLBACK_QSORT_STACK_SIZE ]            ;
  int          stackHi [ FALLBACK_QSORT_STACK_SIZE ]            ;
  ///////////////////////////////////////////////////////////////
  r  = 0                                                        ;
  sp = 0                                                        ;
  fpush ( loSt, hiSt )                                          ;
  ///////////////////////////////////////////////////////////////
  while (sp > 0)                                                {
//    AssertH ( sp < FALLBACK_QSORT_STACK_SIZE - 1, 1004 );
    fpop ( lo, hi )                                             ;
    if ( ( hi - lo ) < FALLBACK_QSORT_SMALL_THRESH)             {
      fallbackSimpleSort ( fmap, eclass, lo, hi )               ;
      continue                                                  ;
    }                                                           ;
    /////////////////////////////////////////////////////////////
    r  = ( (r * 7621) + 1 ) % 32768                             ;
    r3 = r % 3                                                  ;
    if (r3 == 0) med = eclass [ fmap [ lo         ] ]      ; else
    if (r3 == 1) med = eclass [ fmap [ (lo+hi)>>1 ] ]      ; else
                 med = eclass [ fmap [ hi         ] ]           ;
    /////////////////////////////////////////////////////////////
    unLo = ltLo = lo                                            ;
    unHi = gtHi = hi                                            ;
    /////////////////////////////////////////////////////////////
    while (1)                                                   {
      while (1)                                                 {
        if ( unLo > unHi ) break                                ;
          n = ((int)eclass [ fmap[unLo ] ]) - ((int)med)        ;
          if ( n == 0 )                                         {
            fswap ( fmap[unLo] , fmap[ltLo] )                   ;
            ltLo ++                                             ;
            unLo ++                                             ;
            continue                                            ;
          }                                                     ;
          if ( n > 0 ) break                                    ;
          unLo ++                                               ;
        }                                                       ;
        /////////////////////////////////////////////////////////
         while (1)                                              {
           if ( unLo > unHi ) break                             ;
           n = ((int)eclass [ fmap [ unHi ] ]) - ((int)med)     ;
           if ( n == 0 )                                        {
             fswap(fmap[unHi], fmap[gtHi])                      ;
             gtHi --                                            ;
             unHi --                                            ;
             continue                                           ;
           }                                                    ;
           if ( n < 0 ) break                                   ;
           unHi --                                              ;
         }                                                      ;
         if (unLo > unHi) break                                 ;
         fswap(fmap[unLo], fmap[unHi])                          ;
         unLo ++                                                ;
         unHi --                                                ;
      }                                                         ;
      if ( gtHi < ltLo ) continue                               ;
      ///////////////////////////////////////////////////////////
      n = fmin(ltLo-lo, unLo-ltLo); fvswap(lo  , unLo-n, n)     ;
      m = fmin(hi-gtHi, gtHi-unHi); fvswap(unLo, hi-m+1, m)     ;
      n = lo + unLo - ltLo - 1                                  ;
      m = hi - gtHi + unHi + 1                                  ;
      ///////////////////////////////////////////////////////////
      if ( ( n - lo ) > ( hi - m )  )                           {
         fpush ( lo , n  )                                      ;
         fpush ( m  , hi )                                      ;
      } else                                                    {
         fpush ( m  , hi )                                      ;
         fpush ( lo , n  )                                      ;
      }                                                         ;
   }                                                            ;
  ///////////////////////////////////////////////////////////////
  #undef fmin
  #undef fpush
  #undef fpop
  #undef fswap
  #undef fvswap
  #undef FALLBACK_QSORT_SMALL_THRESH
  #undef FALLBACK_QSORT_STACK_SIZE
}

///////////////////////////////////////////////////////////////////////////////

static void fallbackSort            (
              unsigned int * fmap   ,
              unsigned int * eclass ,
              unsigned int * bhtab  ,
              int            nblock ,
              int            verb   )
{
  Q_UNUSED(verb);
  #define       SET_BH(zz)  bhtab[(zz) >> 5] |= (1 << ((zz) & 31))
  #define     CLEAR_BH(zz)  bhtab[(zz) >> 5] &= ~(1 << ((zz) & 31))
  #define     ISSET_BH(zz)  (bhtab[(zz) >> 5] & (1 << ((zz) & 31)))
  #define      WORD_BH(zz)  bhtab[(zz) >> 5]
  #define UNALIGNED_BH(zz)  ((zz) & 0x01f)
  /////////////////////////////////////////////////////////////////////////////
  int             ftab     [ 257 ]                                            ;
  int             ftabCopy [ 256 ]                                            ;
  int             H, i, j, k, l, r, cc, cc1                                   ;
  int             nNotDone                                                    ;
  int             nBhtab                                                      ;
  unsigned char * eclass8 = (unsigned char *)eclass                           ;
  /////////////////////////////////////////////////////////////////////////////
  for ( i = 0 ; i < 257    ; i++ ) ftab     [ i             ]  = 0            ;
  for ( i = 0 ; i < nblock ; i++ ) ftab     [ eclass8 [ i ] ]  ++             ;
  for ( i = 0 ; i < 256    ; i++ ) ftabCopy [ i             ]  = ftab [ i   ] ;
  for ( i = 1 ; i < 257    ; i++ ) ftab     [ i             ] += ftab [ i-1 ] ;
  /////////////////////////////////////////////////////////////////////////////
  for ( i = 0 ; i < nblock ; i++ )                                            {
    j          = eclass8 [ i ]                                                ;
    k          = ftab    [ j ] - 1                                            ;
    ftab [ j ] = k                                                            ;
    fmap [ k ] = i                                                            ;
  }                                                                           ;
  /////////////////////////////////////////////////////////////////////////////
  nBhtab = 2 + ( nblock / 32 )                                                ;
  for ( i = 0 ; i < nBhtab ; i++ ) bhtab [ i ] = 0                            ;
  for ( i = 0 ; i < 256    ; i++ ) SET_BH(ftab[i])                            ;
  /////////////////////////////////////////////////////////////////////////////
  for (i = 0; i < 32; i++)                                                    {
    SET_BH   ( nblock + 2 * i     )                                           ;
    CLEAR_BH ( nblock + 2 * i + 1 )                                           ;
  }                                                                           ;
  /////////////////////////////////////////////////////////////////////////////
  /*--                             the log(N) loop                         --*/
  H = 1                                                                       ;
  while ( 1 )                                                                 {
    for ( i = 0 , j = 0 ; i < nblock ; i++ )                                  {
      if (ISSET_BH(i)) j = i                                                  ;
      k = fmap [ i ] - H                                                      ;
      if (k < 0) k += nblock                                                  ;
      eclass[k] = j                                                           ;
    }                                                                         ;
    ///////////////////////////////////////////////////////////////////////////
    nNotDone =  0                                                             ;
    r        = -1                                                             ;
    ///////////////////////////////////////////////////////////////////////////
    while ( 1 )                                                               {
      k = r + 1                                                               ;
      while (ISSET_BH(k) && UNALIGNED_BH(k)) k++                              ;
      if (ISSET_BH(k))                                                        {
        while (WORD_BH(k) == 0xffffffff) k += 32                              ;
        while (ISSET_BH(k)) k++                                               ;
      }                                                                       ;
      l = k - 1                                                               ;
      if ( l >= nblock ) break                                                ;
      while (!ISSET_BH(k) && UNALIGNED_BH(k)) k++                             ;
      if (!ISSET_BH(k))                                                       {
        while (WORD_BH(k) == 0x00000000) k += 32                              ;
        while (!ISSET_BH(k)) k++                                              ;
      }                                                                       ;
      r = k - 1                                                               ;
      if (r >= nblock) break                                                  ;
      if (r > l)                                                              {
        nNotDone += ( r - l + 1 )                                             ;
        fallbackQSort3 ( fmap, eclass, l, r )                                 ;
        cc = -1                                                               ;
        for (i = l; i <= r; i++)                                              {
          cc1 = eclass [ fmap [ i ] ]                                         ;
          if (cc != cc1) { SET_BH(i); cc = cc1; }                             ;
        }                                                                     ;
      }                                                                       ;
    }                                                                         ;
    ///////////////////////////////////////////////////////////////////////////
    H *= 2                                                                    ;
    if ( ( H > nblock ) || ( nNotDone == 0 ) ) break                          ;
  }                                                                           ;
  j = 0                                                                       ;
  for ( i = 0 ; i < nblock ; i++ )                                            {
    while ( ftabCopy[j] == 0 ) j++                                            ;
    ftabCopy [ j          ] --                                                ;
    eclass8  [ fmap [ i ] ]  = (unsigned char)j                               ;
  }                                                                           ;
  /////////////////////////////////////////////////////////////////////////////
  #undef       SET_BH
  #undef     CLEAR_BH
  #undef     ISSET_BH
  #undef      WORD_BH
  #undef UNALIGNED_BH
}

static inline bool mainGtU                (
                unsigned int     i1       ,
                unsigned int     i2       ,
                unsigned char  * block    ,
                unsigned short * quadrant ,
                unsigned int     nblock   ,
                int            * budget   )
{
  int            k                          ;
  unsigned char  c1, c2                     ;
  unsigned short s1, s2                     ;
  ///////////////////////////////////////////
  #define ABC                               \
    c1 = block[i1]; c2 = block[i2]        ; \
    if (c1 != c2) return (c1 > c2)        ; \
    i1++; i2++                              ;
  ABC                                       ;
  ABC                                       ;
  ABC                                       ;
  ABC                                       ;
  ABC                                       ;
  ABC                                       ;
  ABC                                       ;
  ABC                                       ;
  ABC                                       ;
  ABC                                       ;
  ABC                                       ;
  ABC                                       ;
  #undef  ABC
  ///////////////////////////////////////////
  k = nblock + 8                            ;
  do                                        {
    #define ABC                             \
      c1 = block[i1]; c2 = block[i2]      ; \
      if (c1 != c2) return (c1 > c2)      ; \
      s1 = quadrant[i1]; s2 = quadrant[i2]; \
      if (s1 != s2) return (s1 > s2)      ; \
      i1++; i2++                            ;
    ABC                                     ;
    ABC                                     ;
    ABC                                     ;
    ABC                                     ;
    ABC                                     ;
    ABC                                     ;
    ABC                                     ;
    ABC                                     ;
    #undef  ABC
    /////////////////////////////////////////
    if (i1 >= nblock) i1 -= nblock          ;
    if (i2 >= nblock) i2 -= nblock          ;
    /////////////////////////////////////////
    k -= 8                                  ;
    (*budget)--                             ;
  } while ( k >= 0 )                        ;
  return false                              ;
}

static int
incs[14] =                                                    {
       1 ,       4 ,    13 ,     40 , 121 , 364 , 1093 , 3280 ,
    9841 ,   29524 , 88573 , 265720                           ,
  797161 , 2391484                                          } ;

static void mainSimpleSort              (
              unsigned int   * ptr      ,
              unsigned char  * block    ,
              unsigned short * quadrant ,
              int              nblock   ,
              int              lo       ,
              int              hi       ,
              int              d        ,
              int            *  budget  )
{
  int          i, j, h, bigN, hp     ;
  unsigned int v                     ;
  ////////////////////////////////////
  bigN = hi - lo + 1                 ;
  if (bigN < 2) return               ;
  ////////////////////////////////////
  hp  = 0                            ;
  while (incs[hp] < bigN) hp++       ;
  hp --                              ;
  ////////////////////////////////////
  for ( ; hp >= 0 ; hp-- )           {
    h = incs [ hp ]                  ;
    i = lo + h                       ;
    while ( true )                   {
      if ( i > hi ) break            ;
      v = ptr[i]                     ;
      j = i                          ;
      while ( mainGtU                (
                ptr [ j - h ] + d    ,
                v+d                  ,
                block                ,
                quadrant             ,
                nblock               ,
                budget           ) ) {
        ptr [ j ] = ptr [ j - h ]    ;
        j         =       j - h      ;
        if (j <= (lo + h - 1)) break ;
      }                              ;
      ////////////////////////////////
      ptr [ j ] = v                  ;
      i++                            ;
      if ( i > hi ) break            ;
      ////////////////////////////////
      v = ptr [ i ]                  ;
      j = i                          ;
      ////////////////////////////////
      while ( mainGtU                (
                ptr [ j-h ] + d      ,
                v+d                  ,
                block                ,
                quadrant             ,
                nblock               ,
                budget           ) ) {
        ptr [ j ] = ptr [ j - h ]    ;
        j         =       j - h      ;
        if (j <= (lo + h - 1)) break ;
      }                              ;
      ////////////////////////////////
      ptr [ j ] = v                  ;
      i++                            ;
      if ( i > hi ) break            ;
      ////////////////////////////////
      v = ptr [ i ]                  ;
      j = i                          ;
      ////////////////////////////////
      while ( mainGtU                (
                ptr [ j - h ] + d    ,
                v + d                ,
                block                ,
                quadrant             ,
                nblock               ,
                budget           ) ) {
        ptr [ j ] = ptr [ j - h ]    ;
        j         =       j - h      ;
        if (j <= (lo + h - 1)) break ;
      }                              ;
      ////////////////////////////////
      ptr [ j ] = v                  ;
      i++                            ;
      ////////////////////////////////
      if ( (*budget) < 0) return     ;
    }                                ;
  }                                  ;
}

static inline unsigned char mmed3 (
                unsigned char a   ,
                unsigned char b   ,
                unsigned char c   )
{
  unsigned char t                     ;
  if (a > b) { t = a; a = b; b = t; } ;
  if (b > c)                          {
    b = c                             ;
    if (a > b) b = a                  ;
  }                                   ;
  return b                            ;
}

#define mswap(zz1, zz2) { int zztmp = zz1; zz1 = zz2; zz2 = zztmp; }

#define mvswap(zzp1, zzp2, zzn)   \
{                                 \
  int yyp1 = (zzp1);              \
  int yyp2 = (zzp2);              \
  int yyn  = (zzn);               \
  while (yyn > 0) {               \
    mswap(ptr[yyp1], ptr[yyp2]) ; \
    yyp1++; yyp2++; yyn--;        \
  }                               \
}

#define mmin(a,b) ((a) < (b)) ? (a) : (b)

#define mpush(lz,hz,dz) { stackLo[sp] = lz ; \
                          stackHi[sp] = hz ; \
                          stackD [sp] = dz ; \
                          sp++             ; }

#define mpop(lz,hz,dz) { sp--             ; \
                         lz = stackLo[sp] ; \
                         hz = stackHi[sp] ; \
                         dz = stackD [sp] ; }


#define mnextsize(az) (nextHi[az]-nextLo[az])

#define mnextswap(az,bz)                                        \
   { int tz ;                                                   \
     tz = nextLo[az]; nextLo[az] = nextLo[bz]; nextLo[bz] = tz; \
     tz = nextHi[az]; nextHi[az] = nextHi[bz]; nextHi[bz] = tz; \
     tz = nextD [az]; nextD [az] = nextD [bz]; nextD [bz] = tz; }


#define MAIN_QSORT_SMALL_THRESH 20
#define MAIN_QSORT_DEPTH_THRESH (BZ_N_RADIX + BZ_N_QSORT)
#define MAIN_QSORT_STACK_SIZE   100

static void mainQSort3                  (
              unsigned int   * ptr      ,
              unsigned char  * block    ,
              unsigned short * quadrant ,
              int              nblock   ,
              int              loSt     ,
              int              hiSt     ,
              int              dSt      ,
              int            * budget   )
{
  int unLo, unHi, ltLo, gtHi, n, m, med, sp, lo, hi, d ;
  int stackLo [ MAIN_QSORT_STACK_SIZE ]                ;
  int stackHi [ MAIN_QSORT_STACK_SIZE ]                ;
  int stackD  [ MAIN_QSORT_STACK_SIZE ]                ;
  int nextLo  [ 3                     ]                ;
  int nextHi  [ 3                     ]                ;
  int nextD   [ 3                     ]                ;
  //////////////////////////////////////////////////////
  sp = 0                                               ;
  mpush ( loSt, hiSt, dSt )                            ;
  //////////////////////////////////////////////////////
  while ( sp > 0 )                                     {
    mpop ( lo, hi, d )                                 ;
    if ( ( hi - lo ) < MAIN_QSORT_SMALL_THRESH        ||
         ( d         > MAIN_QSORT_DEPTH_THRESH     ) ) {
      mainSimpleSort                                   (
        ptr                                            ,
        block                                          ,
        quadrant                                       ,
        nblock                                         ,
        lo                                             ,
        hi                                             ,
        d                                              ,
        budget                                       ) ;
      if (*budget < 0) return                          ;
      continue                                         ;
    }                                                  ;
    ////////////////////////////////////////////////////
    med = (int)mmed3 ( block [ ptr[ lo         ]+d ]   ,
                       block [ ptr[ hi         ]+d ]   ,
                       block [ ptr[ (lo+hi)>>1 ]+d ] ) ;
    ////////////////////////////////////////////////////
    unLo = ltLo = lo                                   ;
    unHi = gtHi = hi                                   ;
    ////////////////////////////////////////////////////
    while ( true )                                     {
      while ( true )                                   {
        if ( unLo > unHi ) break                       ;
        n = ( (int) block [ ptr [ unLo ] + d ] ) - med ;
        if (n == 0)                                    {
          mswap ( ptr [ unLo ] , ptr [ ltLo ] )        ;
          ltLo++                                       ;
          unLo++                                       ;
          continue                                     ;
        }                                              ;
        if ( n > 0 ) break                             ;
        unLo++                                         ;
      }                                                ;
      //////////////////////////////////////////////////
      while ( true )                                   {
        if ( unLo > unHi ) break                       ;
        n = ((int) block [ ptr [ unHi ] + d ] ) - med  ;
        if ( n == 0 )                                  {
          mswap ( ptr [ unHi ] , ptr [ gtHi ] )        ;
          gtHi --                                      ;
          unHi --                                      ;
          continue                                     ;
        }                                              ;
        if ( n <  0 ) break                            ;
        unHi--                                         ;
      }                                                ;
      //////////////////////////////////////////////////
      if (unLo > unHi) break                           ;
      mswap(ptr[unLo], ptr[unHi]); unLo++; unHi--      ;
    }                                                  ;
    ////////////////////////////////////////////////////
    ////////////////////////////////////////////////////
    if ( gtHi < ltLo )                                 {
      mpush ( lo , hi , d+1 )                          ;
      continue                                         ;
    }                                                  ;
    ////////////////////////////////////////////////////
    n = mmin(ltLo-lo, unLo-ltLo)                       ;
    mvswap ( lo   , unLo - n     , n )                 ;
    m = mmin(hi-gtHi, gtHi-unHi)                       ;
    mvswap ( unLo , hi   - m + 1 , m )                 ;
    ////////////////////////////////////////////////////
    n = lo + unLo - ltLo - 1                           ;
    m = hi - gtHi + unHi + 1                           ;
    ////////////////////////////////////////////////////
    nextLo[0] = lo  ; nextHi[0] = n   ; nextD[0] = d   ;
    nextLo[1] = m   ; nextHi[1] = hi  ; nextD[1] = d   ;
    nextLo[2] = n+1 ; nextHi[2] = m-1 ; nextD[2] = d+1 ;
    ////////////////////////////////////////////////////
    if (mnextsize(0) < mnextsize(1)) mnextswap(0,1)    ;
    if (mnextsize(1) < mnextsize(2)) mnextswap(1,2)    ;
    if (mnextsize(0) < mnextsize(1)) mnextswap(0,1)    ;
    ////////////////////////////////////////////////////
    ////////////////////////////////////////////////////
    mpush( nextLo [ 0 ] , nextHi [ 0 ] , nextD [ 0 ] ) ;
    mpush( nextLo [ 1 ] , nextHi [ 1 ] , nextD [ 1 ] ) ;
    mpush( nextLo [ 2 ] , nextHi [ 2 ] , nextD [ 2 ] ) ;
  }                                                    ;
}

#undef mswap
#undef mvswap
#undef mpush
#undef mpop
#undef mmin
#undef mnextsize
#undef mnextswap
#undef MAIN_QSORT_SMALL_THRESH
#undef MAIN_QSORT_DEPTH_THRESH
#undef MAIN_QSORT_STACK_SIZE

static void mainSort                    (
              unsigned int   * ptr      ,
              unsigned char  * block    ,
              unsigned short * quadrant ,
              unsigned int   * ftab     ,
              int              nblock   ,
              int              verb     ,
              int            * budget   )
{
  Q_UNUSED(verb);
  #define BIGFREQ(b) (ftab[((b)+1) << 8] - ftab[(b) << 8])
  #define SETMASK (1 << 21)
  #define CLEARMASK (~(SETMASK))
  ///////////////////////////////////////////////////////////////////////////
  int            i , j , k , ss , sb                                        ;
  int            runningOrder [ 256 ]                                       ;
  bool           bigDone      [ 256 ]                                       ;
  int            copyStart    [ 256 ]                                       ;
  int            copyEnd      [ 256 ]                                       ;
  unsigned char  c1                                                         ;
  int            numQSorted                                                 ;
  unsigned short s                                                          ;
  ///////////////////////////////////////////////////////////////////////////
  for ( i = 65536 ; i >= 0 ; i-- ) ftab[i] = 0                              ;
  j = block [ 0 ] << 8                                                      ;
  i = nblock - 1                                                            ;
  ///////////////////////////////////////////////////////////////////////////
  for ( ; i >= 3 ; i -= 4 )                                                 {
    quadrant [ i   ]  = 0                                                   ;
    j                 = (j >> 8) | ( ((unsigned short)block[i  ]) << 8)     ;
    ftab     [ j   ] ++                                                     ;
    quadrant [ i-1 ]  = 0                                                   ;
    j                 = (j >> 8) | ( ((unsigned short)block[i-1]) << 8)     ;
    ftab     [ j   ] ++                                                     ;
    quadrant [ i-2 ]  = 0                                                   ;
    j                 = (j >> 8) | ( ((unsigned short)block[i-2]) << 8)     ;
    ftab     [ j   ] ++                                                     ;
    quadrant [ i-3 ]  = 0                                                   ;
    j                 = (j >> 8) | ( ((unsigned short)block[i-3]) << 8)     ;
    ftab     [ j   ] ++                                                     ;
  }                                                                         ;
  ///////////////////////////////////////////////////////////////////////////
  for ( ; i >= 0 ; i-- )                                                    {
    quadrant [ i ]  = 0                                                     ;
    j = (j >> 8) | ( ((unsigned short)block[i]) << 8)                       ;
    ftab     [ j ] ++                                                       ;
  }                                                                         ;
  ///////////////////////////////////////////////////////////////////////////
  for ( i = 0 ; i < BZ_N_OVERSHOOT ; i++ )                                  {
    block    [ nblock + i ] = block [ i ]                                   ;
    quadrant [ nblock + i ] = 0                                             ;
  }                                                                         ;
  ///////////////////////////////////////////////////////////////////////////
  for ( i = 1 ; i <= 65536 ; i++ ) ftab[i] += ftab[i-1]                     ;
  s = block [ 0 ] << 8                                                      ;
  i = nblock - 1                                                            ;
  ///////////////////////////////////////////////////////////////////////////
  for ( ; i >= 3 ; i -= 4 )                                                 {
    s          = (s >> 8) | (block[i  ] << 8)                               ;
    j          = ftab[s] -1                                                 ;
    ftab [ s ] = j                                                          ;
    ptr  [ j ] = i                                                          ;
    s          = (s >> 8) | (block[i-1] << 8)                               ;
    j          = ftab[s] -1                                                 ;
    ftab [ s ] = j                                                          ;
    ptr  [ j ] = i-1                                                        ;
    s          = (s >> 8) | (block[i-2] << 8)                               ;
    j          = ftab[s] -1                                                 ;
    ftab [ s ] = j                                                          ;
    ptr  [ j ] = i-2                                                        ;
    s          = (s >> 8) | (block[i-3] << 8)                               ;
    j          = ftab[s] -1                                                 ;
    ftab [ s ] = j                                                          ;
    ptr  [ j ] = i-3                                                        ;
  }                                                                         ;
  ///////////////////////////////////////////////////////////////////////////
  for ( ; i >= 0 ; i-- )                                                    {
    s          = (s >> 8) | (block[i] << 8)                                 ;
    j          = ftab[s] -1                                                 ;
    ftab [ s ] = j                                                          ;
    ptr  [ j ] = i                                                          ;
  }                                                                         ;
  ///////////////////////////////////////////////////////////////////////////
  for ( i = 0 ; i <= 255 ; i++ )                                            {
    bigDone      [ i ] = false                                              ;
    runningOrder [ i ] = i                                                  ;
  }                                                                         ;
  ///////////////////////////////////////////////////////////////////////////
  {                                                                         ;
    int vv                                                                  ;
    int h = 1                                                               ;
    do h = ( 3 * h ) + 1 ; while ( h <= 256 )                               ;
    do                                                                      {
      h /= 3                                                                ;
      for ( i = h ; i <= 255 ; i++ )                                        {
        vv = runningOrder[i]                                                ;
        j  = i                                                              ;
        while ( BIGFREQ(runningOrder[j-h]) > BIGFREQ(vv) )                  {
          runningOrder[j] = runningOrder[j-h]                               ;
          j = j - h                                                         ;
          if (j <= (h - 1)) goto zero                                       ;
        }                                                                   ;
        zero                                                                :
        runningOrder[j] = vv                                                ;
      }                                                                     ;
    } while ( h != 1 )                                                      ;
  }                                                                         ;
  ///////////////////////////////////////////////////////////////////////////
  for ( i = 0 , numQSorted = 0 ; i <= 255 ; i++ )                           {
    ss = runningOrder [ i ]                                                 ;
    for ( j = 0 ; j <= 255 ; j++ )                                          {
      if ( j != ss )                                                        {
        sb = ( ss << 8 ) + j                                                ;
        if ( ! (ftab[sb] & SETMASK) )                                       {
          int lo =   ftab [ sb     ] & CLEARMASK                            ;
          int hi = ( ftab [ sb + 1 ] & CLEARMASK ) - 1                      ;
          if ( hi > lo )                                                    {
             mainQSort3                                                     (
               ptr                                                          ,
               block                                                        ,
               quadrant                                                     ,
               nblock                                                       ,
               lo                                                           ,
               hi                                                           ,
               BZ_N_RADIX                                                   ,
               budget                                                     ) ;
             numQSorted += (hi - lo + 1)                                    ;
             if ( (*budget) < 0) return                                     ;
          }                                                                 ;
        }                                                                   ;
        ftab[sb] |= SETMASK                                                 ;
      }                                                                     ;
    }                                                                       ;
    /////////////////////////////////////////////////////////////////////////
    {                                                                       ;
      for ( j = 0 ; j <= 255 ; j++ )                                        {
        copyStart[j] =  ftab[(j << 8) + ss]     & CLEARMASK                 ;
        copyEnd  [j] = (ftab[(j << 8) + ss + 1] & CLEARMASK) - 1            ;
      }                                                                     ;
      for ( j = ftab[ss << 8] & CLEARMASK ; j < copyStart[ss] ; j++ )       {
        k  = ptr   [ j ] - 1                                                ;
        if (k < 0) k += nblock                                              ;
        c1 = block [ k ]                                                    ;
        if ( ! bigDone [ c1 ] ) ptr[ copyStart[c1]++ ] = k                  ;
      }                                                                     ;
      for (j = (ftab[(ss+1) << 8] & CLEARMASK) - 1; j > copyEnd[ss]; j--)   {
        k = ptr    [ j ] - 1                                                ;
        if (k < 0) k += nblock                                              ;
        c1 = block [ k ]                                                    ;
        if ( ! bigDone [ c1 ] ) ptr[ copyEnd[c1]-- ] = k                    ;
      }                                                                     ;
    }                                                                       ;
    /////////////////////////////////////////////////////////////////////////
    for ( j = 0 ; j <= 255 ; j++ ) ftab[(j << 8) + ss] |= SETMASK           ;
    /////////////////////////////////////////////////////////////////////////
    bigDone [ ss ] = true                                                   ;
    /////////////////////////////////////////////////////////////////////////
    if ( i < 255 )                                                          {
      int bbStart =  ftab[ ss    << 8] & CLEARMASK                          ;
      int bbSize  = (ftab[(ss+1) << 8] & CLEARMASK) - bbStart               ;
      int shifts  = 0                                                       ;
      while ( ( bbSize >> shifts ) > 65534 ) shifts++                       ;
      for ( j = bbSize-1 ; j >= 0 ; j-- )                                   {
        int            a2update = ptr [ bbStart + j ]                       ;
        unsigned short qVal     = (unsigned short)( j >> shifts )           ;
        quadrant[a2update]      = qVal                                      ;
        if (a2update < BZ_N_OVERSHOOT) quadrant[a2update + nblock] = qVal   ;
      }                                                                     ;
    }                                                                       ;
  }                                                                         ;
  ///////////////////////////////////////////////////////////////////////////
  #undef BIGFREQ
  #undef SETMASK
  #undef CLEARMASK
}

static inline void upHeap (
         int     z        ,
         int   * heap     ,
         int   * weight   )
{
  int zz  = z                                 ;
  int tmp = heap[zz]                          ;
  int zzz = zz >> 1                           ;
  /////////////////////////////////////////////
  while ( weight[tmp] < weight[ heap[zzz] ] ) {
     heap[zz] = heap[zzz]                     ;
     zz       = zzz                           ;
     zzz    >>= 1                             ;
  }                                           ;
  heap[zz] = tmp                              ;
}

static inline void downHeap (
         int     z          ,
         int     nHeap      ,
         int   * heap       ,
         int   * weight     )
{
  int zz  = z                                        ;
  int tmp = heap[zz]                                 ;
  int yy                                             ;
  ////////////////////////////////////////////////////
  while ( true )                                     {
    yy = zz << 1                                     ;
    if ( yy > nHeap ) break                          ;
    if ( ( yy < nHeap )                             &&
         ( weight[heap[yy+1]] < weight[heap[yy]] ) ) {
      yy++                                           ;
    }                                                ;
    if ( weight[tmp] < weight[ heap [ yy ] ] ) break ;
    heap[zz] = heap[yy]                              ;
    zz       = yy                                    ;
  }                                                  ;
  heap[zz] = tmp                                     ;
}

static void * defaultBzAlloc(void * opaque,int items,int size)
{
  Q_UNUSED(opaque);
  void * v = malloc ( items * size ) ;
  return v                           ;
}

static void defaultBzFree(void * opaque,void * addr)
{
  Q_UNUSED(opaque);
  if ( addr != NULL ) free ( addr ) ;
}

static inline bool bzConfigOk (void)
{
  if (sizeof(int)   != 4) return false ;
  if (sizeof(short) != 2) return false ;
  if (sizeof(char)  != 1) return false ;
  return true                          ;
}

inline int indexIntoF ( int indx , int * cftab )
{
  int nb = 0                                        ;
  int na = 256                                      ;
  int mid                                           ;
  do                                                {
    mid = (nb + na) >> 1                            ;
    if (indx >= cftab[mid]) nb = mid; else na = mid ;
  } while ( ( na - nb ) != 1 )                      ;
  return nb                                         ;
}

static void            BzCodeLengths (
       unsigned char * len           ,
       int           * freq          ,
       int             alphaSize     ,
       int             maxLen        )
{
  #define WEIGHTOF(zz0)  ((zz0) & 0xffffff00)
  #define DEPTHOF(zz1)   ((zz1) & 0x000000ff)
  #define MYMAX(zz2,zz3) ((zz2) > (zz3) ? (zz2) : (zz3))
  #define ADDWEIGHTS(zw1,zw2)                             \
    (WEIGHTOF(zw1)+WEIGHTOF(zw2)) |                       \
    (1 + MYMAX(DEPTHOF(zw1),DEPTHOF(zw2)))
  /////////////////////////////////////////////////////////
  int  heap   [ BZ_MAX_ALPHA_SIZE + 2 ]                   ;
  int  weight [ BZ_MAX_ALPHA_SIZE * 2 ]                   ;
  int  parent [ BZ_MAX_ALPHA_SIZE * 2 ]                   ;
  int  nNodes                                             ;
  int  nHeap                                              ;
  int  n1                                                 ;
  int  n2                                                 ;
  int  i                                                  ;
  int  j                                                  ;
  int  k                                                  ;
  bool tooLong = false                                    ;
  /////////////////////////////////////////////////////////
  for (i = 0; i < alphaSize; i++)                         {
    weight[i+1] = (freq[i] == 0 ? 1 : freq[i]) << 8       ;
  }                                                       ;
  /////////////////////////////////////////////////////////
  while ( true )                                          {
    nNodes       = alphaSize                              ;
    nHeap        =  0                                     ;
    heap   [ 0 ] =  0                                     ;
    weight [ 0 ] =  0                                     ;
    parent [ 0 ] = -2                                     ;
    ///////////////////////////////////////////////////////
    for ( i = 1; i <= alphaSize; i++ )                    {
      parent [ i     ] = -1                               ;
      nHeap ++                                            ;
      heap   [ nHeap ] =  i                               ;
      upHeap ( nHeap , heap , weight )                    ;
    }                                                     ;
    ///////////////////////////////////////////////////////
    while ( nHeap > 1 )                                   {
      n1         = heap [ 1     ]                         ;
      heap [ 1 ] = heap [ nHeap ]                         ;
      nHeap--                                             ;
      downHeap ( 1 , nHeap , heap , weight )              ;
      /////////////////////////////////////////////////////
      n2         = heap [ 1     ]                         ;
      heap [ 1 ] = heap [ nHeap ]                         ;
      nHeap--                                             ;
      downHeap ( 1 , nHeap , heap , weight )              ;
      /////////////////////////////////////////////////////
      nNodes++                                            ;
      parent[n1]     = parent[n2] = nNodes                ;
      weight[nNodes] = ADDWEIGHTS(weight[n1], weight[n2]) ;
      parent[nNodes] = -1                                 ;
      nHeap++                                             ;
      heap  [nHeap]  = nNodes                             ;
      upHeap   ( nHeap , heap , weight )                  ;
    }                                                     ;
    ///////////////////////////////////////////////////////
    tooLong = false                                       ;
    for ( i = 1 ; i <= alphaSize ; i++ )                  {
      j = 0                                               ;
      k = i                                               ;
      while ( parent[k] >= 0 )                            {
        k = parent[k]                                     ;
        j++                                               ;
      }                                                   ;
      len[i-1] = j                                        ;
      if (j > maxLen) tooLong = true                      ;
    }                                                     ;
    if (!tooLong) break                                   ;
    ///////////////////////////////////////////////////////
    for ( i = 1; i <= alphaSize ; i++ )                   {
      j            = weight[i] >> 8                       ;
      j            = 1          + ( j / 2 )               ;
      weight [ i ] = j         << 8                       ;
    }                                                     ;
  }                                                       ;
  /////////////////////////////////////////////////////////
  #undef WEIGHTOF
  #undef DEPTHOF
  #undef MYMAX
  #undef ADDWEIGHTS
}

static void            BzAssignCodes (
       int           * code          ,
       unsigned char * length        ,
       int             minLen        ,
       int             maxLen        ,
       int             alphaSize     )
{
  int vec = 0                            ;
  int n                                  ;
  int i                                  ;
  ////////////////////////////////////////
  for ( n = minLen ; n <= maxLen ; n++ ) {
    for (i = 0; i < alphaSize; i++)      {
      if (length[i] == n)                {
        code [ i ] = vec                 ;
        vec++                            ;
      }                                  ;
    }                                    ;
    vec <<= 1                            ;
  }                                      ;
}

static void            BzDecodeTables (
       int           * limit          ,
       int           * base           ,
       int           * perm           ,
       unsigned char * length         ,
       int             minLen         ,
       int             maxLen         ,
       int             alphaSize      )
{
  int pp  = 0                                  ;
  int vec = 0                                  ;
  int i                                        ;
  int j                                        ;
  //////////////////////////////////////////////
  for ( i = minLen ; i <= maxLen ; i++ )       {
    for ( j = 0; j < alphaSize; j++ )          {
      if (length[j] == i)                      {
        perm[pp] = j                           ;
        pp++                                   ;
      }                                        ;
    }                                          ;
  }                                            ;
  //////////////////////////////////////////////
  for (i = 0; i < BZ_MAX_CODE_LEN; i++)        {
    base[i] = 0                                ;
  }                                            ;
  for (i = 0; i < alphaSize; i++)              {
    base[length[i]+1]++                        ;
  }                                            ;
  for (i = 1; i < BZ_MAX_CODE_LEN; i++)        {
    base[i] += base[i-1]                       ;
  }                                            ;
  //////////////////////////////////////////////
  for (i = 0; i < BZ_MAX_CODE_LEN; i++)        {
    limit[i] = 0                               ;
  }                                            ;
  //////////////////////////////////////////////
  for ( i = minLen ; i <= maxLen ; i++ )       {
    vec     += (base[i+1] - base[i])           ;
    limit[i] = vec-1                           ;
    vec    <<= 1                               ;
  }                                            ;
  //////////////////////////////////////////////
  for (i = minLen + 1; i <= maxLen; i++)       {
    base[i] = ((limit[i-1] + 1) << 1) - base[i];
 }                                             ;
}

static inline void makeMaps_e ( EState * s )
{
  int i                                   ;
  s -> nInUse = 0                         ;
  for (i = 0; i < 256; i++)               {
    if (s->inUse[i])                      {
      s -> unseqToSeq [ i ] = s -> nInUse ;
      s -> nInUse ++                      ;
    }                                     ;
  }                                       ;
}

static inline void prepare_new_block ( EState* s )
{
  int i                            ;
  s -> nblock        = 0           ;
  s -> numZ          = 0           ;
  s -> state_out_pos = 0           ;
  s -> blockCRC      = 0xffffffffL ;
  for (i = 0; i < 256; i++)        {
    s->inUse[i] = false            ;
  }                                ;
  s -> blockNo++                   ;
}

static inline void init_RL ( EState * s )
{
  s -> state_in_ch  = 256 ;
  s -> state_in_len = 0   ;
}

static inline bool isempty_RL ( EState * s )
{
  return ! ( ( s->state_in_ch  < 256 )  &&
             ( s->state_in_len > 0   ) ) ;
}

static void BZ2_bsInitWrite ( EState * s )
{
   s->bsLive = 0 ;
   s->bsBuff = 0 ;
}

static void bsFinishWrite ( EState* s )
{
  while ( s->bsLive > 0 )                                       {
    s -> zbits [ s->numZ ] = (unsigned char)( s->bsBuff >> 24 ) ;
    s -> numZ    ++                                             ;
    s -> bsBuff <<= 8                                           ;
    s -> bsLive  -= 8                                           ;
  } ;
}

static inline void bsW ( EState * s, int n, unsigned int v )
{
  while ( s -> bsLive >= 8 )                                    {
    s -> zbits [ s->numZ ] = (unsigned char)( s->bsBuff >> 24 ) ;
    s -> numZ    ++                                             ;
    s -> bsBuff <<= 8                                           ;
    s -> bsLive  -= 8                                           ;
  }                                                             ;
  s -> bsBuff |= (v << (32 - s->bsLive - n))                    ;
  s -> bsLive += n                                              ;
}

static void bsPutUInt32 ( EState * s, unsigned int u )
{
   bsW ( s, 8, (u >> 24) & 0xffL ) ;
   bsW ( s, 8, (u >> 16) & 0xffL ) ;
   bsW ( s, 8, (u >>  8) & 0xffL ) ;
   bsW ( s, 8,  u        & 0xffL ) ;
}

static void bsPutUChar ( EState * s, unsigned char c )
{
   bsW ( s, 8, (unsigned int)c   ) ;
}

static void add_pair_to_block ( EState * s )
{
  unsigned char ch = (unsigned char)(s->state_in_ch)           ;
  int           i                                              ;
  for (i = 0; i < s->state_in_len; i++)                        {
    BZ_UPDATE_CRC ( s->blockCRC , ch )                         ;
  }                                                            ;
  s -> inUse [ s -> state_in_ch ] = true                       ;
  switch ( s -> state_in_len )                                 {
    case 1                                                     :
      s->block[s->nblock] = (unsigned char)ch; s->nblock++     ;
    break                                                      ;
    case 2                                                     :
      s->block[s->nblock] = (unsigned char)ch; s->nblock++     ;
      s->block[s->nblock] = (unsigned char)ch; s->nblock++     ;
    break                                                      ;
    case 3                                                     :
      s->block[s->nblock] = (unsigned char)ch; s->nblock++     ;
      s->block[s->nblock] = (unsigned char)ch; s->nblock++     ;
      s->block[s->nblock] = (unsigned char)ch; s->nblock++     ;
    break                                                      ;
    default                                                    :
      s->inUse[s->state_in_len-4] = true                       ;
      s->block[s->nblock] = (unsigned char)ch ; s->nblock++    ;
      s->block[s->nblock] = (unsigned char)ch ; s->nblock++    ;
      s->block[s->nblock] = (unsigned char)ch ; s->nblock++    ;
      s->block[s->nblock] = (unsigned char)ch ; s->nblock++    ;
      s->block[s->nblock] = (unsigned char)(s->state_in_len-4) ;
      s->nblock++                                              ;
    break                                                      ;
  }                                                            ;
}

static void flush_RL ( EState * s )
{
  if ( s->state_in_ch < 256 ) add_pair_to_block ( s ) ;
  init_RL ( s )                                       ;
}

static void BzBlockSort ( EState * s )
{
  unsigned int   * ptr    = s -> ptr                                ;
  unsigned char  * block  = s -> block                              ;
  unsigned int   * ftab   = s -> ftab                               ;
  int              nblock = s -> nblock                             ;
  int              verb   = s -> verbosity                          ;
  int              wfact  = s -> workFactor                         ;
  unsigned short * quadrant                                         ;
  int              budget                                           ;
  int              budgetInit                                       ;
  int              i                                                ;
  ///////////////////////////////////////////////////////////////////
  if (nblock < 10000)                                               {
    fallbackSort ( s->arr1 , s->arr2 , ftab , nblock , verb )       ;
  } else                                                            {
    i = nblock + BZ_N_OVERSHOOT                                     ;
    if (i & 1) i++                                                  ;
    quadrant = (unsigned short *)(&(block[i]))                      ;
    if ( wfact < 1   ) wfact = 1                                    ;
    if ( wfact > 100 ) wfact = 100                                  ;
    budgetInit = nblock * ( ( wfact - 1 ) / 3 )                     ;
    budget     = budgetInit                                         ;
    mainSort ( ptr, block, quadrant, ftab, nblock, verb, &budget  ) ;
    if (budget < 0)                                                 {
      fallbackSort ( s->arr1 , s->arr2 , ftab , nblock , verb )     ;
    }                                                               ;
  }                                                                 ;
  ///////////////////////////////////////////////////////////////////
  s -> origPtr = -1                                                 ;
  for (i = 0; i < s->nblock; i++)                                   {
    if ( ptr[i] == 0 )                                              {
      s -> origPtr = i                                              ;
      break                                                         ;
    }                                                               ;
  }                                                                 ;
}

#define ADD_CHAR_TO_BLOCK(zs,zchh0)                         \
{                                                           \
  unsigned int zchh = (unsigned int)(zchh0);                \
  if (zchh != zs->state_in_ch && zs->state_in_len == 1 )  { \
     unsigned char ch = (unsigned char)(zs->state_in_ch)  ; \
     BZ_UPDATE_CRC( zs->blockCRC, ch );                     \
     zs->inUse[zs->state_in_ch] = true;                     \
     zs->block[zs->nblock] = (unsigned char)ch ;            \
     zs->nblock++;                                          \
     zs->state_in_ch = zchh;                                \
  }                                                         \
  else                                                      \
  if (zchh != zs->state_in_ch || zs->state_in_len == 255) { \
    if (zs->state_in_ch < 256) add_pair_to_block ( zs )   ; \
     zs->state_in_ch = zchh;                                \
     zs->state_in_len = 1;                                  \
  } else {                                                  \
     zs->state_in_len++;                                    \
  }                                                         \
}

static bool copy_input_until_stop ( EState * s )
{
  bool progress_in = false                                        ;
  if ( s->mode == BZ_M_RUNNING )                                  {
    while ( true )                                                {
      if ( s->nblock         >= s->nblockMAX ) break              ;
      if ( s->strm->avail_in == 0            ) break              ;
      progress_in = true                                          ;
      ADD_CHAR_TO_BLOCK                                           (
        s                                                         ,
        (unsigned int)(*((unsigned char *)(s->strm->next_in)))  ) ;
      s -> strm -> next_in       ++                               ;
      s -> strm -> avail_in      --                               ;
      s -> strm -> total_in_lo32 ++                               ;
      if (s->strm->total_in_lo32 == 0) s -> strm->total_in_hi32++ ;
    }                                                             ;
  } else                                                          {
    while ( true )                                                {
      if ( s->nblock          >= s->nblockMAX ) break             ;
      if ( s->strm->avail_in  == 0            ) break             ;
      if ( s->avail_in_expect == 0            ) break             ;
      progress_in = true                                          ;
      ADD_CHAR_TO_BLOCK                                           (
        s                                                         ,
        (unsigned int)(*((unsigned char *)(s->strm->next_in)))  ) ;
      s -> strm->next_in       ++                                 ;
      s -> strm->avail_in      --                                 ;
      s -> strm->total_in_lo32 ++                                 ;
      if (s->strm->total_in_lo32 == 0) s->strm->total_in_hi32++   ;
      s->avail_in_expect       --                                 ;
    }                                                             ;
  }                                                               ;
  return progress_in                                              ;
}

static bool copy_output_until_stop ( EState * s )
{
  bool progress_out = false                                     ;
  while ( true )                                                {
    if (s->strm->avail_out == 0      ) break                    ;
    if (s->state_out_pos   >= s->numZ) break                    ;
    progress_out         = true                                 ;
    *(s->strm->next_out) = s->zbits[s->state_out_pos]           ;
    s -> state_out_pos        ++                                ;
    s -> strm->avail_out      --                                ;
    s -> strm->next_out       ++                                ;
    s -> strm->total_out_lo32 ++                                ;
    if (s->strm->total_out_lo32 == 0) s->strm->total_out_hi32++ ;
  }                                                             ;
  return progress_out                                           ;
}

static void generateMTFValues ( EState * s )
{
  unsigned char    yy [ 256 ]                                       ;
  int              i                                                ;
  int              j                                                ;
  int              zPend                                            ;
  int              wr                                               ;
  int              EOB                                              ;
  unsigned int   * ptr   = s -> ptr                                 ;
  unsigned char  * block = s -> block                               ;
  unsigned short * mtfv  = s -> mtfv                                ;
  ///////////////////////////////////////////////////////////////////
  makeMaps_e ( s )                                                  ;
  EOB = s -> nInUse + 1                                             ;
  for ( i = 0 ; i <= EOB      ; i++ ) s -> mtfFreq [ i ] = 0        ;
  ///////////////////////////////////////////////////////////////////
  wr    = 0                                                         ;
  zPend = 0                                                         ;
  for ( i = 0 ; i < s->nInUse ; i++ ) yy [ i ] = (unsigned char) i  ;
  ///////////////////////////////////////////////////////////////////
  for ( i = 0 ; i < s->nblock ; i++ )                               {
    unsigned char ll_i                                              ;
    j = ptr [ i ] - 1                                               ;
    if (j < 0) j += s->nblock                                       ;
    ll_i = s -> unseqToSeq [ block [ j ] ]                          ;
    /////////////////////////////////////////////////////////////////
    if (yy[0] == ll_i)                                              {
      zPend ++                                                      ;
    } else                                                          {
      if ( zPend > 0 )                                              {
        zPend--                                                     ;
        while ( true )                                              {
          if ( zPend & 1 )                                          {
            mtfv[wr] = BZ_RUNB                                      ;
            wr ++                                                   ;
            s->mtfFreq[BZ_RUNB]++                                   ;
          } else                                                    {
            mtfv[wr] = BZ_RUNA                                      ;
            wr++                                                    ;
            s->mtfFreq[BZ_RUNA]++                                   ;
          }                                                         ;
          if ( zPend < 2 ) break                                    ;
          zPend -= 2                                                ;
          zPend /= 2                                                ;
        }                                                           ;
        zPend = 0                                                   ;
      }                                                             ;
      {                                                             ;
        register unsigned char   rtmp                               ;
        register unsigned char * ryy_j                              ;
        register unsigned char   rll_i                              ;
        rtmp  = yy[1]                                               ;
        yy[1] = yy[0]                                               ;
        ryy_j = &(yy[1])                                            ;
        rll_i = ll_i                                                ;
        while ( rll_i != rtmp )                                     {
          register unsigned char rtmp2                              ;
          ryy_j++                                                   ;
          rtmp2  = rtmp                                             ;
          rtmp   = *ryy_j                                           ;
          *ryy_j = rtmp2                                            ;
        }                                                           ;
        yy[0]    = rtmp                                             ;
        j        = ryy_j - &(yy[0])                                 ;
        mtfv[wr] = j+1                                              ;
        wr++                                                        ;
        s->mtfFreq[j+1]++                                           ;
      }                                                             ;
    }                                                               ;
  }                                                                 ;
  ///////////////////////////////////////////////////////////////////
  if (zPend > 0)                                                    {
    zPend--                                                         ;
    while ( true )                                                  {
      if ( zPend & 1 )                                              {
        mtfv[wr] = BZ_RUNB                                          ;
        wr++                                                        ;
        s->mtfFreq[BZ_RUNB]++                                       ;
      } else                                                        {
        mtfv[wr] = BZ_RUNA                                          ;
        wr++                                                        ;
        s->mtfFreq[BZ_RUNA]++                                       ;
      }                                                             ;
      if (zPend < 2) break                                          ;
      zPend -= 2                                                    ;
      zPend /= 2                                                    ;
    }                                                               ;
    zPend = 0                                                       ;
  }                                                                 ;
  ///////////////////////////////////////////////////////////////////
  mtfv[wr] = EOB                                                    ;
  wr++                                                              ;
  s->mtfFreq[EOB]++                                                 ;
  s->nMTF  = wr                                                     ;
}

static void sendMTFValues ( EState* s )
{
  #define BZ_LESSER_ICOST  0
  #define BZ_GREATER_ICOST 15
  ///////////////////////////////////////////////////////////////////
  int v, t, i, j, gs, ge, totc, bt, bc, iter                        ;
  int nSelectors, alphaSize, minLen, maxLen, selCtr,nGroups, nBytes ;
  unsigned short   cost [ BZ_N_GROUPS ]                             ;
  int              fave [ BZ_N_GROUPS ]                             ;
  unsigned short * mtfv = s->mtfv                                   ;
  ///////////////////////////////////////////////////////////////////
  alphaSize = s->nInUse + 2                                         ;
  for ( t = 0 ; t < BZ_N_GROUPS ; t++ )                             {
    for ( v = 0 ; v < alphaSize ; v++ )                             {
      s->len[t][v] = BZ_GREATER_ICOST                               ;
    }                                                               ;
  }                                                                 ;
  ///////////////////////////////////////////////////////////////////
  if ( s->nMTF <  200 ) nGroups = 2                            ; else
  if ( s->nMTF <  600 ) nGroups = 3                            ; else
  if ( s->nMTF < 1200 ) nGroups = 4                            ; else
  if ( s->nMTF < 2400 ) nGroups = 5                            ; else
                        nGroups = 6                                 ;
  ///////////////////////////////////////////////////////////////////
  {                                                                 ;
    int nPart, remF, tFreq, aFreq                                   ;
    nPart = nGroups                                                 ;
    remF  = s->nMTF                                                 ;
    gs    = 0                                                       ;
    /////////////////////////////////////////////////////////////////
    while ( nPart > 0 )                                             {
      tFreq = remF / nPart                                          ;
      ge    = gs-1                                                  ;
      aFreq = 0                                                     ;
      while ( ( aFreq < tFreq ) && ( ge < ( alphaSize - 1 ) ) )     {
        ge++                                                        ;
        aFreq += s->mtfFreq[ge]                                     ;
      }                                                             ;
      ///////////////////////////////////////////////////////////////
      if ( ( ge > gs ) && ( nPart != nGroups ) && ( nPart != 1 )   &&
           ( ( (nGroups-nPart) % 2 ) == 1) )                        {
        aFreq -= s->mtfFreq[ge]                                     ;
        ge--                                                        ;
      }                                                             ;
      ///////////////////////////////////////////////////////////////
      for ( v = 0 ; v < alphaSize ; v++ )                           {
        if ( ( v >= gs ) && ( v <= ge ) )                           {
          s->len[nPart-1][v] = BZ_LESSER_ICOST                      ;
        } else                                                      {
          s->len[nPart-1][v] = BZ_GREATER_ICOST                     ;
        }                                                           ;
      }                                                             ;
      nPart--                                                       ;
      gs    = ge+1                                                  ;
      remF -= aFreq                                                 ;
    }                                                               ;
  }                                                                 ;
  ///////////////////////////////////////////////////////////////////
  for ( iter = 0 ; iter < BZ_N_ITERS ; iter++ )                     {
    for ( t = 0 ; t < nGroups ; t++ ) fave[t] = 0                   ;
    for ( t = 0 ; t < nGroups ; t++ )                               {
      for ( v = 0 ; v < alphaSize ; v++ ) s->rfreq[t][v] = 0        ;
    }                                                               ;
    if (nGroups == 6)                                               {
      for ( v = 0 ; v < alphaSize ; v++ )                           {
        s->len_pack[v][0] = (s->len[1][v] << 16) | s->len[0][v]     ;
        s->len_pack[v][1] = (s->len[3][v] << 16) | s->len[2][v]     ;
        s->len_pack[v][2] = (s->len[5][v] << 16) | s->len[4][v]     ;
      }                                                             ;
    }                                                               ;
    /////////////////////////////////////////////////////////////////
    nSelectors = 0                                                  ;
    totc       = 0                                                  ;
    gs         = 0                                                  ;
    while ( true )                                                  {
      if ( gs >= s->nMTF ) break                                    ;
      ge = gs + BZ_G_SIZE - 1                                       ;
      if ( ge >= s->nMTF ) ge = s->nMTF-1                           ;
      for ( t = 0 ; t < nGroups ; t++ ) cost[t] = 0                 ;
      if ( ( nGroups == 6 ) && ( 50 == ( ge - gs + 1 ) ) )          {
        register unsigned int   cost01, cost23, cost45              ;
        register unsigned short icv                                 ;
        cost01 = cost23 = cost45 = 0                                ;
        #define BZ_ITER(nn)                                         \
          icv     = mtfv        [ gs+(nn)   ]                     ; \
          cost01 += s->len_pack [ icv ] [ 0 ]                     ; \
          cost23 += s->len_pack [ icv ] [ 1 ]                     ; \
          cost45 += s->len_pack [ icv ] [ 2 ]                       ;
        BZ_ITER( 0); BZ_ITER( 1); BZ_ITER( 2); BZ_ITER( 3)          ;
        BZ_ITER( 4); BZ_ITER( 5); BZ_ITER( 6); BZ_ITER( 7)          ;
        BZ_ITER( 8); BZ_ITER( 9); BZ_ITER(10); BZ_ITER(11)          ;
        BZ_ITER(12); BZ_ITER(13); BZ_ITER(14); BZ_ITER(15)          ;
        BZ_ITER(16); BZ_ITER(17); BZ_ITER(18); BZ_ITER(19)          ;
        BZ_ITER(20); BZ_ITER(21); BZ_ITER(22); BZ_ITER(23)          ;
        BZ_ITER(24); BZ_ITER(25); BZ_ITER(26); BZ_ITER(27)          ;
        BZ_ITER(28); BZ_ITER(29); BZ_ITER(30); BZ_ITER(31)          ;
        BZ_ITER(32); BZ_ITER(33); BZ_ITER(34); BZ_ITER(35)          ;
        BZ_ITER(36); BZ_ITER(37); BZ_ITER(38); BZ_ITER(39)          ;
        BZ_ITER(40); BZ_ITER(41); BZ_ITER(42); BZ_ITER(43)          ;
        BZ_ITER(44); BZ_ITER(45); BZ_ITER(46); BZ_ITER(47)          ;
        BZ_ITER(48); BZ_ITER(49)                                    ;
        #undef BZ_ITER
        cost[0] = cost01 & 0xffff; cost[1] = cost01 >> 16           ;
        cost[2] = cost23 & 0xffff; cost[3] = cost23 >> 16           ;
        cost[4] = cost45 & 0xffff; cost[5] = cost45 >> 16           ;
      } else                                                        {
        for (i = gs; i <= ge; i++)                                  {
          unsigned short icv = mtfv[i]                              ;
          for ( t = 0 ; t < nGroups ; t++ )                         {
            cost[t] += s->len[t][icv]                               ;
          }                                                         ;
        }                                                           ;
      }                                                             ;
      ///////////////////////////////////////////////////////////////
      bc = 999999999                                                ;
      bt = -1                                                       ;
      for ( t = 0 ; t < nGroups ; t++ )                             {
        if ( cost[t] < bc )                                         {
          bc = cost [ t ]                                           ;
          bt = t                                                    ;
        }                                                           ;
      }                                                             ;
      totc        += bc                                             ;
      fave [ bt ] ++                                                ;
      s->selector[nSelectors] = bt                                  ;
      nSelectors++                                                  ;
      ///////////////////////////////////////////////////////////////
      if ( ( nGroups == 6 ) && ( 50 == ( ge - gs + 1 ) ) )          {
        #define BZ_ITUR(nn) s->rfreq[bt][ mtfv[gs+(nn)] ]++
        BZ_ITUR( 0); BZ_ITUR( 1); BZ_ITUR( 2); BZ_ITUR( 3)          ;
        BZ_ITUR( 4); BZ_ITUR( 5); BZ_ITUR( 6); BZ_ITUR( 7)          ;
        BZ_ITUR( 8); BZ_ITUR( 9); BZ_ITUR(10); BZ_ITUR(11)          ;
        BZ_ITUR(12); BZ_ITUR(13); BZ_ITUR(14); BZ_ITUR(15)          ;
        BZ_ITUR(16); BZ_ITUR(17); BZ_ITUR(18); BZ_ITUR(19)          ;
        BZ_ITUR(20); BZ_ITUR(21); BZ_ITUR(22); BZ_ITUR(23)          ;
        BZ_ITUR(24); BZ_ITUR(25); BZ_ITUR(26); BZ_ITUR(27)          ;
        BZ_ITUR(28); BZ_ITUR(29); BZ_ITUR(30); BZ_ITUR(31)          ;
        BZ_ITUR(32); BZ_ITUR(33); BZ_ITUR(34); BZ_ITUR(35)          ;
        BZ_ITUR(36); BZ_ITUR(37); BZ_ITUR(38); BZ_ITUR(39)          ;
        BZ_ITUR(40); BZ_ITUR(41); BZ_ITUR(42); BZ_ITUR(43)          ;
        BZ_ITUR(44); BZ_ITUR(45); BZ_ITUR(46); BZ_ITUR(47)          ;
        BZ_ITUR(48); BZ_ITUR(49)                                    ;
        #undef BZ_ITUR
      } else                                                        {
        for (i = gs; i <= ge; i++) s->rfreq[bt][ mtfv[i] ]++        ;
      }                                                             ;
      gs = ge+1                                                     ;
    }                                                               ;
    /////////////////////////////////////////////////////////////////
    for ( t = 0 ; t < nGroups ; t++ )                               {
       BzCodeLengths                                                (
         & ( s -> len   [t][0] )                                    ,
         & ( s -> rfreq [t][0] )                                    ,
         alphaSize                                                  ,
         17 /*20*/                                                ) ;
    }                                                               ;
  }                                                                 ;
  ///////////////////////////////////////////////////////////////////
  {                                                                 ;
    unsigned char pos[BZ_N_GROUPS], ll_i, tmp2, tmp                 ;
    for ( i = 0 ; i < nGroups    ; i++ ) pos[i] = i                 ;
    for ( i = 0 ; i < nSelectors ; i++ )                            {
      ll_i = s -> selector [ i ]                                    ;
      j    = 0                                                      ;
      tmp  = pos           [ j ]                                    ;
      ///////////////////////////////////////////////////////////////
      while ( ll_i != tmp )                                         {
        j++                                                         ;
        tmp2      = tmp                                             ;
        tmp       = pos [ j ]                                       ;
        pos [ j ] = tmp2                                            ;
      }                                                             ;
      pos [ 0 ]              = tmp                                  ;
      s -> selectorMtf [ i ] = j                                    ;
    }                                                               ;
  }                                                                 ;
  ///////////////////////////////////////////////////////////////////
  for ( t = 0 ; t < nGroups ; t++ )                                 {
    minLen = 32                                                     ;
    maxLen =  0                                                     ;
    for (i = 0; i < alphaSize; i++)                                 {
      if (s->len[t][i] > maxLen) maxLen = s->len[t][i]              ;
      if (s->len[t][i] < minLen) minLen = s->len[t][i]              ;
    }                                                               ;
    BzAssignCodes                                                   (
      & ( s -> code [ t ] [ 0 ] )                                   ,
      & ( s -> len  [ t ] [ 0 ] )                                   ,
      minLen                                                        ,
      maxLen                                                        ,
      alphaSize                                                   ) ;
  }                                                                 ;
  ///////////////////////////////////////////////////////////////////
  {                                                                 ;
    bool inUse16 [ 16 ]                                             ;
    for ( i = 0 ; i < 16 ; i++ )                                    {
      inUse16[i] = false                                            ;
      for (j = 0; j < 16; j++)                                      {
         if ( s -> inUse [ (i * 16) + j ] ) inUse16[i] = true       ;
      }                                                             ;
    }                                                               ;
    nBytes = s->numZ                                                ;
    for (i = 0; i < 16; i++)                                        {
      if (inUse16[i]) bsW(s,1,1); else bsW(s,1,0)                   ;
    }                                                               ;
    for (i = 0; i < 16; i++)                                        {
      if ( inUse16[i] )                                             {
        for (j = 0; j < 16; j++)                                    {
          if ( s->inUse[i * 16 + j] ) bsW(s,1,1); else bsW(s,1,0)   ;
        }                                                           ;
      }                                                             ;
    }                                                               ;
  }                                                                 ;
  ///////////////////////////////////////////////////////////////////
  nBytes = s->numZ                                                  ;
  bsW ( s,  3, nGroups    )                                         ;
  bsW ( s, 15, nSelectors )                                         ;
  for ( i = 0 ; i < nSelectors ; i++ )                              {
    for ( j = 0; j < s->selectorMtf[i] ; j++ ) bsW(s,1,1)           ;
    bsW ( s , 1 , 0 )                                               ;
  }                                                                 ;
  ///////////////////////////////////////////////////////////////////
  nBytes = s->numZ                                                  ;
  for ( t = 0 ; t < nGroups ; t++ )                                 {
    int curr = s->len [ t ] [ 0 ]                                   ;
    bsW ( s, 5, curr )                                              ;
    for (i = 0; i < alphaSize; i++)                                 {
      while (curr < s->len[t][i]) { bsW(s,2,2); curr++; /* 10 */ }  ;
      while (curr > s->len[t][i]) { bsW(s,2,3); curr--; /* 11 */ }  ;
      bsW ( s, 1, 0 )                                               ;
    }                                                               ;
  }                                                                 ;
  ///////////////////////////////////////////////////////////////////
  nBytes = s->numZ                                                  ;
  selCtr = 0                                                        ;
  gs     = 0                                                        ;
  ///////////////////////////////////////////////////////////////////
  while ( true )                                                    {
    if ( gs >= s->nMTF ) break                                      ;
    ge = gs + BZ_G_SIZE - 1                                         ;
    if (ge >= s->nMTF) ge = s->nMTF-1                               ;
    if ( ( nGroups == 6 ) && ( 50 == ( ge - gs + 1 ) ) )            {
      unsigned short  mtfv_i                                        ;
      unsigned char * s_len_sel_selCtr
                    = &(s->len[s->selector[selCtr]][0])             ;
      int           * s_code_sel_selCtr
                    = &(s->code[s->selector[selCtr]][0])            ;
      #define BZ_ITAH(nn)                                           \
         mtfv_i = mtfv [ gs + nn ]                                ; \
         bsW ( s                                                  , \
               s_len_sel_selCtr  [ mtfv_i ]                       , \
               s_code_sel_selCtr [ mtfv_i ]                         )
      BZ_ITAH( 0); BZ_ITAH( 1); BZ_ITAH( 2); BZ_ITAH( 3)            ;
      BZ_ITAH( 4); BZ_ITAH( 5); BZ_ITAH( 6); BZ_ITAH( 7)            ;
      BZ_ITAH( 8); BZ_ITAH( 9); BZ_ITAH(10); BZ_ITAH(11)            ;
      BZ_ITAH(12); BZ_ITAH(13); BZ_ITAH(14); BZ_ITAH(15)            ;
      BZ_ITAH(16); BZ_ITAH(17); BZ_ITAH(18); BZ_ITAH(19)            ;
      BZ_ITAH(20); BZ_ITAH(21); BZ_ITAH(22); BZ_ITAH(23)            ;
      BZ_ITAH(24); BZ_ITAH(25); BZ_ITAH(26); BZ_ITAH(27)            ;
      BZ_ITAH(28); BZ_ITAH(29); BZ_ITAH(30); BZ_ITAH(31)            ;
      BZ_ITAH(32); BZ_ITAH(33); BZ_ITAH(34); BZ_ITAH(35)            ;
      BZ_ITAH(36); BZ_ITAH(37); BZ_ITAH(38); BZ_ITAH(39)            ;
      BZ_ITAH(40); BZ_ITAH(41); BZ_ITAH(42); BZ_ITAH(43)            ;
      BZ_ITAH(44); BZ_ITAH(45); BZ_ITAH(46); BZ_ITAH(47)            ;
      BZ_ITAH(48); BZ_ITAH(49)                                      ;
      #undef  BZ_ITAH
    } else                                                          {
      for ( i = gs ; i <= ge ; i++ )                                {
        bsW ( s                                                     ,
              s->len  [ s -> selector [ selCtr ] ] [ mtfv[i] ]      ,
              s->code [ s -> selector [ selCtr ] ] [ mtfv[i] ]    ) ;
      }                                                             ;
    }                                                               ;
    gs      = ge + 1                                                ;
    selCtr ++                                                       ;
  }                                                                 ;
  ///////////////////////////////////////////////////////////////////
  #undef  BZ_LESSER_ICOST
  #undef  BZ_GREATER_ICOST
}

void BzCompressBlock ( EState * s , bool is_last_block )
{
  if (s->nblock > 0)                                                     {
    BZ_FINALISE_CRC ( s->blockCRC )                                      ;
    s->combinedCRC  = (s->combinedCRC << 1) | (s->combinedCRC >> 31)     ;
    s->combinedCRC ^= s->blockCRC                                        ;
    if (s->blockNo > 1) s->numZ = 0                                      ;
    BzBlockSort ( s )                                                    ;
  }                                                                      ;
  ////////////////////////////////////////////////////////////////////////
  s->zbits = (unsigned char *) (&((unsigned char *)s->arr2)[s->nblock])  ;
  ////////////////////////////////////////////////////////////////////////
  if (s->blockNo == 1)                                                   {
    BZ2_bsInitWrite ( s                                                ) ;
    bsPutUChar      ( s , BZ_HDR_B                                     ) ;
    bsPutUChar      ( s , BZ_HDR_Z                                     ) ;
    bsPutUChar      ( s , BZ_HDR_h                                     ) ;
    bsPutUChar      ( s , (unsigned char)(BZ_HDR_0 + s->blockSize100k) ) ;
  }                                                                      ;
  ////////////////////////////////////////////////////////////////////////
  if ( s->nblock > 0 )                                                   {
    bsPutUChar        ( s , 0x31            )                            ;
    bsPutUChar        ( s , 0x41            )                            ;
    bsPutUChar        ( s , 0x59            )                            ;
    bsPutUChar        ( s , 0x26            )                            ;
    bsPutUChar        ( s , 0x53            )                            ;
    bsPutUChar        ( s , 0x59            )                            ;
    bsPutUInt32       ( s , s->blockCRC     )                            ;
    bsW               ( s ,  1 , 0          )                            ;
    bsW               ( s , 24 , s->origPtr )                            ;
    generateMTFValues ( s                   )                            ;
    sendMTFValues     ( s                   )                            ;
  }                                                                      ;
  ////////////////////////////////////////////////////////////////////////
  if (is_last_block)                                                     {
    bsPutUChar    ( s, 0x17           )                                  ;
    bsPutUChar    ( s, 0x72           )                                  ;
    bsPutUChar    ( s, 0x45           )                                  ;
    bsPutUChar    ( s, 0x38           )                                  ;
    bsPutUChar    ( s, 0x50           )                                  ;
    bsPutUChar    ( s, 0x90           )                                  ;
    bsPutUInt32   ( s, s->combinedCRC )                                  ;
    bsFinishWrite ( s                 )                                  ;
  }                                                                      ;
}

static inline void makeMaps_d ( DState * s )
{
  int i                                   ;
  s -> nInUse = 0                         ;
  for (i = 0; i < 256; i++)               {
    if (s->inUse[i])                      {
      s -> seqToUnseq [ s -> nInUse ] = i ;
      s -> nInUse ++                      ;
    }                                     ;
  }                                       ;
}

static bool unRLE_obuf_to_output_FAST ( DState* s )
{
  unsigned char k1                                                        ;
  if ( s -> blockRandomised )                                             {
    while ( true )                                                        {
      while ( true )                                                      {
        if ( s -> strm->avail_out == 0 ) return false                     ;
        if ( s -> state_out_len   == 0 ) break                            ;
        *( (unsigned char *)(s->strm->next_out) ) = s->state_out_ch       ;
        BZ_UPDATE_CRC ( s->calculatedBlockCRC , s->state_out_ch )         ;
        s -> state_out_len        --                                      ;
        s -> strm->next_out       ++                                      ;
        s -> strm->avail_out      --                                      ;
        s -> strm->total_out_lo32 ++                                      ;
        if (s->strm->total_out_lo32 == 0) s->strm->total_out_hi32++       ;
      }                                                                   ;
      /////////////////////////////////////////////////////////////////////
      if ( s -> nblock_used == ( s -> save_nblock + 1 ) ) return false    ;
      if ( s -> nblock_used  > ( s -> save_nblock + 1 ) ) return true     ;
      /////////////////////////////////////////////////////////////////////
      s -> state_out_len = 1                                              ;
      s -> state_out_ch  = s->k0                                          ;
      /////////////////////////////////////////////////////////////////////
      BZ_GET_FAST(k1)                                                     ;
      BZ_RAND_UPD_MASK                                                    ;
      k1 ^= BZ_RAND_MASK                                                  ;
      s -> nblock_used ++                                                 ;
      if ( s -> nblock_used == ( s -> save_nblock + 1 ) ) continue        ;
      if ( k1               !=   s -> k0                )                 {
        s->k0 = k1                                                        ;
        continue                                                          ;
      }                                                                   ;
      /////////////////////////////////////////////////////////////////////
      s -> state_out_len = 2                                              ;
      BZ_GET_FAST(k1)                                                     ;
      BZ_RAND_UPD_MASK                                                    ;
      k1 ^= BZ_RAND_MASK                                                  ;
      s  -> nblock_used ++                                                ;
      if (s->nblock_used == s->save_nblock+1) continue                    ;
      if (k1 != s->k0) { s->k0 = k1; continue; }                          ;
      /////////////////////////////////////////////////////////////////////
      s->state_out_len = 3                                                ;
      BZ_GET_FAST(k1)                                                     ;
      BZ_RAND_UPD_MASK                                                    ;
      k1 ^= BZ_RAND_MASK                                                  ;
      s  -> nblock_used++                                                 ;
      if (s->nblock_used == (s->save_nblock+1)) continue                  ;
      if (k1 != s->k0) { s->k0 = k1; continue; }                          ;
      /////////////////////////////////////////////////////////////////////
      BZ_GET_FAST(k1)                                                     ;
      BZ_RAND_UPD_MASK                                                    ;
      k1 ^= BZ_RAND_MASK                                                  ;
      s  -> nblock_used++                                                 ;
      s  -> state_out_len = ((int)k1) + 4                                 ;
      BZ_GET_FAST(s->k0)                                                  ;
      BZ_RAND_UPD_MASK                                                    ;
      s->k0 ^= BZ_RAND_MASK                                               ;
      s->nblock_used++                                                    ;
    }                                                                     ;
  } else                                                                  {
    unsigned int    c_calculatedBlockCRC = s->calculatedBlockCRC          ;
    unsigned char   c_state_out_ch       = s->state_out_ch                ;
    int             c_state_out_len      = s->state_out_len               ;
    int             c_nblock_used        = s->nblock_used                 ;
    int             c_k0                 = s->k0                          ;
    unsigned int  * c_tt                 = s->tt                          ;
    unsigned int    c_tPos               = s->tPos                        ;
    char          * cs_next_out          = s->strm->next_out              ;
    unsigned int    cs_avail_out         = s->strm->avail_out             ;
    int             ro_blockSize100k     = s->blockSize100k               ;
    unsigned int    avail_out_INIT       = cs_avail_out                   ;
    int             s_save_nblockPP      = s->save_nblock+1               ;
    unsigned int    total_out_lo32_old                                    ;
    ///////////////////////////////////////////////////////////////////////
    while ( true )                                                        {
      if ( c_state_out_len > 0 )                                          {
        while ( true )                                                    {
          if ( cs_avail_out    == 0 ) goto return_notr                    ;
          if ( c_state_out_len == 1 ) break                               ;
          *( (unsigned char *)(cs_next_out) ) = c_state_out_ch            ;
          BZ_UPDATE_CRC ( c_calculatedBlockCRC, c_state_out_ch )          ;
          c_state_out_len --                                              ;
          cs_next_out     ++                                              ;
          cs_avail_out    --                                              ;
        }                                                                 ;
        s_state_out_len_eq_one                                            :
        {                                                                 ;
          if (cs_avail_out == 0)                                          {
            c_state_out_len = 1; goto return_notr                         ;
          }                                                               ;
          *( (unsigned char *)(cs_next_out) )  = c_state_out_ch           ;
          BZ_UPDATE_CRC ( c_calculatedBlockCRC , c_state_out_ch )         ;
          cs_next_out  ++                                                 ;
          cs_avail_out --                                                 ;
        }                                                                 ;
      }                                                                   ;
      /////////////////////////////////////////////////////////////////////
      if ( c_nblock_used  > s_save_nblockPP ) return true                 ;
      if ( c_nblock_used == s_save_nblockPP )                             {
        c_state_out_len = 0                                               ;
        goto return_notr                                                  ;
      }                                                                   ;
      c_state_out_ch = c_k0                                               ;
      BZ_GET_FAST_C(k1)                                                   ;
      c_nblock_used ++                                                    ;
      if ( k1 != c_k0 )                                                   {
        c_k0 = k1                                                         ;
        goto s_state_out_len_eq_one                                       ;
      }                                                                   ;
      if (c_nblock_used == s_save_nblockPP) goto s_state_out_len_eq_one   ;
      /////////////////////////////////////////////////////////////////////
      c_state_out_len = 2                                                 ;
      BZ_GET_FAST_C(k1)                                                   ;
      c_nblock_used ++                                                    ;
      if ( c_nblock_used == s_save_nblockPP) continue                     ;
      if ( k1            != c_k0           ) { c_k0 = k1; continue; }     ;
      /////////////////////////////////////////////////////////////////////
      c_state_out_len = 3                                                 ;
      BZ_GET_FAST_C(k1)                                                   ;
      c_nblock_used ++                                                    ;
      if ( c_nblock_used == s_save_nblockPP ) continue                    ;
      if ( k1            != c_k0            ) { c_k0 = k1; continue; }    ;
      /////////////////////////////////////////////////////////////////////
      BZ_GET_FAST_C(k1)                                                   ;
      c_nblock_used++                                                     ;
      c_state_out_len = ((int)k1) + 4                                     ;
      BZ_GET_FAST_C(c_k0)                                                 ;
      c_nblock_used++                                                     ;
    }                                                                     ;
    ///////////////////////////////////////////////////////////////////////
    return_notr                                                           :
    total_out_lo32_old = s->strm->total_out_lo32                          ;
    s->strm->total_out_lo32 += (avail_out_INIT - cs_avail_out)            ;
    if ( s->strm->total_out_lo32 < total_out_lo32_old )                   {
      s->strm->total_out_hi32++                                           ;
    }                                                                     ;
    ///////////////////////////////////////////////////////////////////////
    s -> calculatedBlockCRC = c_calculatedBlockCRC                        ;
    s -> state_out_ch       = c_state_out_ch                              ;
    s -> state_out_len      = c_state_out_len                             ;
    s -> nblock_used        = c_nblock_used                               ;
    s -> k0                 = c_k0                                        ;
    s -> tt                 = c_tt                                        ;
    s -> tPos               = c_tPos                                      ;
    s -> strm->next_out     = cs_next_out                                 ;
    s -> strm->avail_out    = cs_avail_out                                ;
  }                                                                       ;
  return false                                                            ;
}

static bool unRLE_obuf_to_output_SMALL ( DState* s )
{
  unsigned char k1                                                        ;
  if ( s -> blockRandomised )                                             {
    while ( true )                                                        {
      while ( true )                                                      {
        if ( s -> strm->avail_out == 0 ) return false                     ;
        if ( s -> state_out_len   == 0 ) break                            ;
        *( (unsigned char *)(s->strm->next_out) ) = s->state_out_ch       ;
        BZ_UPDATE_CRC ( s->calculatedBlockCRC , s->state_out_ch )         ;
        s -> state_out_len        --                                      ;
        s -> strm->next_out       ++                                      ;
        s -> strm->avail_out      --                                      ;
        s -> strm->total_out_lo32 ++                                      ;
        if ( s -> strm->total_out_lo32 == 0 ) s -> strm->total_out_hi32++ ;
      }                                                                   ;
      /////////////////////////////////////////////////////////////////////
      if ( s -> nblock_used == ( s -> save_nblock + 1 ) ) return false    ;
      if ( s -> nblock_used  > ( s -> save_nblock + 1 ) ) return true     ;
      /////////////////////////////////////////////////////////////////////
      s -> state_out_len = 1                                              ;
      s -> state_out_ch  = s -> k0                                        ;
      BZ_GET_SMALL(k1)                                                    ;
      BZ_RAND_UPD_MASK                                                    ;
      k1 ^= BZ_RAND_MASK                                                  ;
      s->nblock_used++                                                    ;
      if ( s -> nblock_used == s -> save_nblock+1) continue               ;
      if ( k1               != s -> k0           )                        {
        s->k0 = k1                                                        ;
        continue                                                          ;
      }                                                                   ;
      /////////////////////////////////////////////////////////////////////
      s->state_out_len = 2                                                ;
      BZ_GET_SMALL(k1)                                                    ;
      BZ_RAND_UPD_MASK                                                    ;
      k1 ^= BZ_RAND_MASK                                                  ;
      s->nblock_used++                                                    ;
      if ( s->nblock_used == ( s->save_nblock + 1 ) ) continue            ;
      if ( k1             !=   s->k0                )                     {
        s->k0 = k1                                                        ;
        continue                                                          ;
      }                                                                   ;
      /////////////////////////////////////////////////////////////////////
      s->state_out_len = 3                                                ;
      BZ_GET_SMALL(k1)                                                    ;
      BZ_RAND_UPD_MASK                                                    ;
      k1 ^= BZ_RAND_MASK                                                  ;
      s->nblock_used++                                                    ;
      if (s->nblock_used == s->save_nblock+1) continue                    ;
      if (k1 != s->k0) { s->k0 = k1; continue; }                          ;
      /////////////////////////////////////////////////////////////////////
      BZ_GET_SMALL(k1)                                                    ;
      BZ_RAND_UPD_MASK                                                    ;
      k1 ^= BZ_RAND_MASK                                                  ;
      s->nblock_used++                                                    ;
      s->state_out_len = ((int)k1) + 4                                    ;
      BZ_GET_SMALL(s->k0)                                                 ;
      BZ_RAND_UPD_MASK                                                    ;
      s->k0 ^= BZ_RAND_MASK                                               ;
      s->nblock_used++                                                    ;
    }                                                                     ;
  } else                                                                  {
    while ( true )                                                        {
      while ( true )                                                      {
        if ( s -> strm -> avail_out == 0 ) return false                   ;
        if ( s -> state_out_len     == 0 ) break                          ;
        *( (unsigned char *)(s->strm->next_out) ) = s->state_out_ch       ;
        BZ_UPDATE_CRC ( s->calculatedBlockCRC, s->state_out_ch )          ;
        s -> state_out_len        --                                      ;
        s -> strm->next_out       ++                                      ;
        s -> strm->avail_out      --                                      ;
        s -> strm->total_out_lo32 ++                                      ;
        if ( s->strm->total_out_lo32 == 0 ) s->strm->total_out_hi32++     ;
      }                                                                   ;
      /////////////////////////////////////////////////////////////////////
      if ( s -> nblock_used == ( s -> save_nblock + 1 ) ) return false    ;
      if ( s -> nblock_used  > ( s -> save_nblock + 1 ) ) return true     ;
      /////////////////////////////////////////////////////////////////////
      s -> state_out_len = 1                                              ;
      s -> state_out_ch  = s->k0                                          ;
      BZ_GET_SMALL(k1)                                                    ;
      s -> nblock_used ++                                                 ;
      if ( s -> nblock_used == ( s -> save_nblock + 1 ) ) continue        ;
      if ( k1               != s->k0 ) { s->k0 = k1; continue; }          ;
      /////////////////////////////////////////////////////////////////////
      s->state_out_len = 2                                                ;
      BZ_GET_SMALL(k1)                                                    ;
      s->nblock_used++                                                    ;
      if ( s -> nblock_used == ( s -> save_nblock + 1 ) ) continue        ;
      if ( k1               !=  s->k0         ) { s->k0 = k1; continue; } ;
      /////////////////////////////////////////////////////////////////////
      s -> state_out_len = 3                                              ;
      BZ_GET_SMALL(k1)                                                    ;
      s -> nblock_used++                                                  ;
      if ( s -> nblock_used == ( s -> save_nblock + 1 ) ) continue        ;
      if ( k1               !=   s -> k0  ) { s->k0 = k1; continue; }     ;
      /////////////////////////////////////////////////////////////////////
      BZ_GET_SMALL(k1)                                                    ;
      s -> nblock_used  ++                                                ;
      s -> state_out_len = ((int)k1) + 4                                  ;
      BZ_GET_SMALL(s->k0)                                                 ;
      s -> nblock_used  ++                                                ;
    }                                                                     ;
  }                                                                       ;
}

int BzDecompress ( DState * s )
{
  BzStream    * strm = s->strm                                            ;
  unsigned char uc                                                        ;
  int           retVal                                                    ;
  int           minLen                                                    ;
  int           maxLen                                                    ;
  int           i                                                         ;
  int           j                                                         ;
  int           t                                                         ;
  int           alphaSize                                                 ;
  int           nGroups                                                   ;
  int           nSelectors                                                ;
  int           EOB                                                       ;
  int           groupNo                                                   ;
  int           groupPos                                                  ;
  int           nextSym                                                   ;
  int           nblockMAX                                                 ;
  int           nblock                                                    ;
  int           es                                                        ;
  int           N                                                         ;
  int           curr                                                      ;
  int           zt                                                        ;
  int           zn                                                        ;
  int           zvec                                                      ;
  int           zj                                                        ;
  int           gSel                                                      ;
  int           gMinlen                                                   ;
  int         * gLimit                                                    ;
  int         * gBase                                                     ;
  int         * gPerm                                                     ;
  /////////////////////////////////////////////////////////////////////////
  if ( s->state == BZ_X_MAGIC_1 )                                         {
    s -> save_i           = 0                                             ;
    s -> save_j           = 0                                             ;
    s -> save_t           = 0                                             ;
    s -> save_alphaSize   = 0                                             ;
    s -> save_nGroups     = 0                                             ;
    s -> save_nSelectors  = 0                                             ;
    s -> save_EOB         = 0                                             ;
    s -> save_groupNo     = 0                                             ;
    s -> save_groupPos    = 0                                             ;
    s -> save_nextSym     = 0                                             ;
    s -> save_nblockMAX   = 0                                             ;
    s -> save_nblock      = 0                                             ;
    s -> save_es          = 0                                             ;
    s -> save_N           = 0                                             ;
    s -> save_curr        = 0                                             ;
    s -> save_zt          = 0                                             ;
    s -> save_zn          = 0                                             ;
    s -> save_zvec        = 0                                             ;
    s -> save_zj          = 0                                             ;
    s -> save_gSel        = 0                                             ;
    s -> save_gMinlen     = 0                                             ;
    s -> save_gLimit      = NULL                                          ;
    s -> save_gBase       = NULL                                          ;
    s -> save_gPerm       = NULL                                          ;
  }                                                                       ;
  /////////////////////////////////////////////////////////////////////////
  i          = s -> save_i                                                ;
  j          = s -> save_j                                                ;
  t          = s -> save_t                                                ;
  alphaSize  = s -> save_alphaSize                                        ;
  nGroups    = s -> save_nGroups                                          ;
  nSelectors = s -> save_nSelectors                                       ;
  EOB        = s -> save_EOB                                              ;
  groupNo    = s -> save_groupNo                                          ;
  groupPos   = s -> save_groupPos                                         ;
  nextSym    = s -> save_nextSym                                          ;
  nblockMAX  = s -> save_nblockMAX                                        ;
  nblock     = s -> save_nblock                                           ;
  es         = s -> save_es                                               ;
  N          = s -> save_N                                                ;
  curr       = s -> save_curr                                             ;
  zt         = s -> save_zt                                               ;
  zn         = s -> save_zn                                               ;
  zvec       = s -> save_zvec                                             ;
  zj         = s -> save_zj                                               ;
  gSel       = s -> save_gSel                                             ;
  gMinlen    = s -> save_gMinlen                                          ;
  gLimit     = s -> save_gLimit                                           ;
  gBase      = s -> save_gBase                                            ;
  gPerm      = s -> save_gPerm                                            ;
  retVal     = BZ_OK                                                      ;
  /////////////////////////////////////////////////////////////////////////
  switch ( s -> state )                                                   {
    GET_UCHAR(BZ_X_MAGIC_1, uc)                                           ;
    if (uc != BZ_HDR_B) RETURN(BZ_DATA_ERROR_MAGIC)                       ;
    GET_UCHAR(BZ_X_MAGIC_2, uc)                                           ;
    if (uc != BZ_HDR_Z) RETURN(BZ_DATA_ERROR_MAGIC)                       ;
    GET_UCHAR(BZ_X_MAGIC_3, uc)                                           ;
    if (uc != BZ_HDR_h) RETURN(BZ_DATA_ERROR_MAGIC)                       ;
    GET_BITS(BZ_X_MAGIC_4, s->blockSize100k, 8)                           ;
    if ( s->blockSize100k < (BZ_HDR_0 + 1)                               ||
         s->blockSize100k > (BZ_HDR_0 + 9)                                )
      RETURN ( BZ_DATA_ERROR_MAGIC )                                      ;
    s -> blockSize100k -= BZ_HDR_0                                        ;
    ///////////////////////////////////////////////////////////////////////
    if ( s -> smallDecompress )                                           {
      s -> ll16 = (unsigned short *) BZALLOC                              (
                    s->blockSize100k*100000*sizeof(unsigned short)      ) ;
      s -> ll4  = (unsigned char *)BZALLOC                                (
                 ((1+s->blockSize100k*100000)>> 1)*sizeof(unsigned char)) ;
      if ( s->ll16 == NULL || s->ll4 == NULL ) RETURN(BZ_MEM_ERROR)       ;
    } else                                                                {
      s->tt  = (unsigned int *)BZALLOC                                    (
                  s->blockSize100k * 100000 * sizeof(int)               ) ;
      if ( s->tt == NULL ) RETURN(BZ_MEM_ERROR)                           ;
    }                                                                     ;
    ///////////////////////////////////////////////////////////////////////
    GET_UCHAR(BZ_X_BLKHDR_1, uc)                                          ;
    if (uc == 0x17) goto endhdr_2                                         ;
    if (uc != 0x31) RETURN(BZ_DATA_ERROR)                                 ;
    GET_UCHAR(BZ_X_BLKHDR_2, uc)                                          ;
    if (uc != 0x41) RETURN(BZ_DATA_ERROR)                                 ;
    GET_UCHAR(BZ_X_BLKHDR_3, uc)                                          ;
    if (uc != 0x59) RETURN(BZ_DATA_ERROR)                                 ;
    GET_UCHAR(BZ_X_BLKHDR_4, uc)                                          ;
    if (uc != 0x26) RETURN(BZ_DATA_ERROR)                                 ;
    GET_UCHAR(BZ_X_BLKHDR_5, uc)                                          ;
    if (uc != 0x53) RETURN(BZ_DATA_ERROR)                                 ;
    GET_UCHAR(BZ_X_BLKHDR_6, uc)                                          ;
    if (uc != 0x59) RETURN(BZ_DATA_ERROR)                                 ;
    ///////////////////////////////////////////////////////////////////////
    s -> currBlockNo   ++                                                 ;
    s -> storedBlockCRC = 0                                               ;
    ///////////////////////////////////////////////////////////////////////
    GET_UCHAR(BZ_X_BCRC_1, uc)                                            ;
    s->storedBlockCRC = (s->storedBlockCRC << 8) | ((unsigned int)uc)     ;
    GET_UCHAR(BZ_X_BCRC_2, uc)                                            ;
    s->storedBlockCRC = (s->storedBlockCRC << 8) | ((unsigned int)uc)     ;
    GET_UCHAR(BZ_X_BCRC_3, uc)                                            ;
    s->storedBlockCRC = (s->storedBlockCRC << 8) | ((unsigned int)uc)     ;
    GET_UCHAR(BZ_X_BCRC_4, uc)                                            ;
    s->storedBlockCRC = (s->storedBlockCRC << 8) | ((unsigned int)uc)     ;
    GET_BITS(BZ_X_RANDBIT, s->blockRandomised, 1)                         ;
    s->origPtr        = 0                                                 ;
    GET_UCHAR(BZ_X_ORIGPTR_1, uc)                                         ;
    s->origPtr        = (s->origPtr << 8) | ((int)uc)                     ;
    GET_UCHAR(BZ_X_ORIGPTR_2, uc)                                         ;
    s->origPtr        = (s->origPtr << 8) | ((int)uc)                     ;
    GET_UCHAR(BZ_X_ORIGPTR_3, uc)                                         ;
    s->origPtr        = (s->origPtr << 8) | ((int)uc)                     ;
    ///////////////////////////////////////////////////////////////////////
    if (s->origPtr < 0                             ) RETURN(BZ_DATA_ERROR);
    if (s->origPtr > 10 + (100000*s->blockSize100k)) RETURN(BZ_DATA_ERROR);
    ///////////////////////////////////////////////////////////////////////
    for ( i = 0; i < 16 ; i++ )                                           {
      GET_BIT(BZ_X_MAPPING_1, uc)                                         ;
      if (uc == 1) s->inUse16[i] = true                              ; else
                   s->inUse16[i] = false                                  ;
    }                                                                     ;
    ///////////////////////////////////////////////////////////////////////
    for ( i = 0 ; i < 256 ; i++ ) s->inUse[i] = false                     ;
    for ( i = 0 ; i <  16 ; i++ )                                         {
      if ( s -> inUse16 [ i ] )                                           {
        for ( j = 0 ; j < 16 ; j++ )                                      {
          GET_BIT(BZ_X_MAPPING_2, uc)                                     ;
          if (uc == 1) s->inUse [ ( i * 16 ) + j ] = true                 ;
        }                                                                 ;
      }                                                                   ;
    }                                                                     ;
    ///////////////////////////////////////////////////////////////////////
    makeMaps_d ( s )                                                      ;
    if (s->nInUse == 0) RETURN ( BZ_DATA_ERROR )                          ;
    alphaSize = s->nInUse + 2                                             ;
    ///////////////////////////////////////////////////////////////////////
    GET_BITS(BZ_X_SELECTOR_1, nGroups   ,  3)                             ;
    if ( ( nGroups < 2 ) || ( nGroups > 6 ) ) RETURN(BZ_DATA_ERROR)       ;
    GET_BITS(BZ_X_SELECTOR_2, nSelectors, 15)                             ;
    if (nSelectors < 1                      ) RETURN(BZ_DATA_ERROR)       ;
    ///////////////////////////////////////////////////////////////////////
    for ( i = 0 ; i < nSelectors ; i++ )                                  {
      j = 0                                                               ;
      while ( true )                                                      {
        GET_BIT(BZ_X_SELECTOR_3, uc)                                      ;
        if ( uc == 0 ) break                                              ;
        j++                                                               ;
        if (j >= nGroups) RETURN(BZ_DATA_ERROR)                           ;
      }                                                                   ;
      s -> selectorMtf [ i ] = j                                          ;
    }                                                                     ;
    ///////////////////////////////////////////////////////////////////////
    {                                                                     ;
      unsigned char pos[BZ_N_GROUPS], tmp, v                              ;
      for ( v = 0 ; v < nGroups    ; v++ ) pos[v] = v                     ;
      for ( i = 0 ; i < nSelectors ; i++ )                                {
        v   = s -> selectorMtf [ i ]                                      ;
        tmp = pos              [ v ]                                      ;
        while (v > 0)                                                     {
          pos[v] = pos[v-1]                                               ;
          v--                                                             ;
        }                                                                 ;
        pos [ 0 ]      = tmp                                              ;
        s->selector[i] = tmp                                              ;
      }                                                                   ;
    }                                                                     ;
    ///////////////////////////////////////////////////////////////////////
    for ( t = 0 ; t < nGroups ; t++ )                                     {
      GET_BITS(BZ_X_CODING_1, curr, 5)                                    ;
      for ( i = 0 ; i < alphaSize ; i++ )                                 {
        while ( true )                                                    {
          if (curr < 1 || curr > 20) RETURN(BZ_DATA_ERROR)                ;
          GET_BIT(BZ_X_CODING_2, uc)                                      ;
          if (uc == 0) break                                              ;
          GET_BIT(BZ_X_CODING_3, uc)                                      ;
          if (uc == 0) curr++; else curr--                                ;
        }                                                                 ;
        s->len[t][i] = curr                                               ;
      }                                                                   ;
    }                                                                     ;
    ///////////////////////////////////////////////////////////////////////
    for ( t = 0 ; t < nGroups ; t++ )                                     {
      minLen = 32                                                         ;
      maxLen =  0                                                         ;
      for (i = 0; i < alphaSize; i++)                                     {
        if (s->len[t][i] > maxLen) maxLen = s->len[t][i]                  ;
        if (s->len[t][i] < minLen) minLen = s->len[t][i]                  ;
      }                                                                   ;
      BzDecodeTables                                                      (
        & ( s -> limit [ t ] [ 0 ] )                                      ,
        & ( s -> base  [ t ] [ 0 ] )                                      ,
        & ( s -> perm  [ t ] [ 0 ] )                                      ,
        & ( s -> len   [ t ] [ 0 ] )                                      ,
        minLen                                                            ,
        maxLen                                                            ,
        alphaSize                                                       ) ;
      s -> minLens [ t ] = minLen                                         ;
    }                                                                     ;
    ///////////////////////////////////////////////////////////////////////
    EOB       = s -> nInUse + 1                                           ;
    nblockMAX = 100000      * s -> blockSize100k                          ;
    groupNo   = -1                                                        ;
    groupPos  = 0                                                         ;
    for ( i = 0 ; i <= 255 ; i++ ) s->unzftab[i] = 0                      ;
    ///////////////////////////////////////////////////////////////////////
    {                                                                     ;
      int ii, jj, kk                                                      ;
      kk = MTFA_SIZE-1                                                    ;
      for ( ii = 256 / MTFL_SIZE - 1 ; ii >= 0 ; ii-- )                   {
        for ( jj = MTFL_SIZE-1 ; jj >= 0 ; jj-- )                         {
          s -> mtfa [ kk ] = (unsigned char)( ( ii * MTFL_SIZE ) + jj )   ;
          kk--                                                            ;
        }                                                                 ;
        s -> mtfbase [ ii ] = kk + 1                                      ;
      }                                                                   ;
    }                                                                     ;
    ///////////////////////////////////////////////////////////////////////
    nblock = 0                                                            ;
    GET_MTF_VAL(BZ_X_MTF_1, BZ_X_MTF_2, nextSym)                          ;
    ///////////////////////////////////////////////////////////////////////
    while ( true )                                                        {
      if ( nextSym == EOB                           ) break               ;
      if ( nextSym == BZ_RUNA || nextSym == BZ_RUNB )                     {
        es = -1                                                           ;
        N  =  1                                                           ;
        ///////////////////////////////////////////////////////////////////
        do                                                                {
          if (N >= 2*1024*1024) RETURN(BZ_DATA_ERROR)                     ;
          if (nextSym == BZ_RUNA) es = es + (0+1) * N                ; else
          if (nextSym == BZ_RUNB) es = es + (1+1) * N                     ;
          N *= 2                                                          ;
          GET_MTF_VAL(BZ_X_MTF_3, BZ_X_MTF_4, nextSym)                    ;
        } while ( nextSym == BZ_RUNA || nextSym == BZ_RUNB )              ;
        ///////////////////////////////////////////////////////////////////
        es++                                                              ;
        uc              = s -> seqToUnseq [ s->mtfa [ s -> mtfbase[0] ] ] ;
        s->unzftab[uc] += es                                              ;
        ///////////////////////////////////////////////////////////////////
        if (s->smallDecompress)                                           {
          while (es > 0)                                                  {
            if (nblock >= nblockMAX) RETURN(BZ_DATA_ERROR)                ;
            s->ll16[nblock] = (unsigned short)uc                          ;
            nblock++                                                      ;
            es--                                                          ;
          }                                                               ;
        } else                                                            {
          while ( es > 0 )                                                {
            if (nblock >= nblockMAX) RETURN(BZ_DATA_ERROR)                ;
            s->tt[nblock] = (unsigned int)uc                              ;
            nblock ++                                                     ;
            es     --                                                     ;
          }                                                               ;
        }                                                                 ;
        continue                                                          ;
      } else                                                              {
        if (nblock >= nblockMAX) RETURN(BZ_DATA_ERROR)                    ;
        {                                                                 ;
          int          ii , jj , kk , pp , lno , off                      ;
          unsigned int nn                                                 ;
          nn = (unsigned int)( nextSym - 1 )                              ;
          if ( nn < MTFL_SIZE )                                           {
            pp = s -> mtfbase [ 0       ]                                 ;
            uc = s -> mtfa    [ pp + nn ]                                 ;
            while ( nn > 3 )                                              {
              int z = pp + nn                                             ;
              s -> mtfa [ (z)     ] = s -> mtfa [ (z) - 1 ]               ;
              s -> mtfa [ (z) - 1 ] = s -> mtfa [ (z) - 2 ]               ;
              s -> mtfa [ (z) - 2 ] = s -> mtfa [ (z) - 3 ]               ;
              s -> mtfa [ (z) - 3 ] = s -> mtfa [ (z) - 4 ]               ;
              nn                   -= 4                                   ;
            }                                                             ;
            while ( nn > 0 )                                              {
              s -> mtfa [ ( pp + nn ) ] = s -> mtfa [ ( pp + nn ) - 1 ]   ;
              nn--                                                        ;
            }                                                             ;
            s -> mtfa [ pp ] = uc                                         ;
          } else                                                          {
            lno = ( nn / MTFL_SIZE )                                      ;
            off = ( nn % MTFL_SIZE )                                      ;
            pp  = s -> mtfbase [ lno ] + off                              ;
            uc  = s -> mtfa    [ pp  ]                                    ;
            while ( pp > s -> mtfbase [ lno ] )                           {
              s -> mtfa [ pp ] = s -> mtfa [ pp - 1 ]                     ;
              pp--                                                        ;
            }                                                             ;
            s -> mtfbase [ lno ] ++                                       ;
            while ( lno > 0 )                                             {
              s -> mtfbase [ lno ] --                                     ;
              s -> mtfa    [ s -> mtfbase [ lno ] ]                       =
                s -> mtfa  [ s -> mtfbase [ lno - 1 ] + MTFL_SIZE - 1   ] ;
              lno--                                                       ;
            }                                                             ;
            s -> mtfbase [ 0                  ] --                        ;
            s -> mtfa    [ s -> mtfbase [ 0 ] ]  = uc                     ;
            if (s->mtfbase[0] == 0)                                       {
              kk = MTFA_SIZE-1                                            ;
              for ( ii = 256 / MTFL_SIZE-1 ; ii >= 0 ; ii-- )             {
                for (jj = MTFL_SIZE-1; jj >= 0; jj--)                     {
                  s -> mtfa [ kk ] = s -> mtfa [ s -> mtfbase [ii] + jj]  ;
                  kk--                                                    ;
                }                                                         ;
                s -> mtfbase [ ii ] = kk + 1                              ;
              }                                                           ;
            }                                                             ;
          }                                                               ;
        }                                                                 ;
        ///////////////////////////////////////////////////////////////////
        s -> unzftab [ s -> seqToUnseq [ uc ] ] ++                        ;
        if ( s ->smallDecompress )                                        {
          s->ll16[nblock] = (unsigned short)(s->seqToUnseq[uc])           ;
        } else                                                            {
          s->tt  [nblock] = (unsigned int  )(s->seqToUnseq[uc])           ;
        }                                                                 ;
        nblock++                                                          ;
        GET_MTF_VAL(BZ_X_MTF_5, BZ_X_MTF_6, nextSym)                      ;
        continue                                                          ;
      }                                                                   ;
    }                                                                     ;
    ///////////////////////////////////////////////////////////////////////
    if (s->origPtr < 0 || s->origPtr >= nblock) RETURN(BZ_DATA_ERROR)     ;
    for ( i = 0 ; i <= 255 ; i++ )                                        {
      if (s->unzftab[i]<0 || s->unzftab[i]>nblock) RETURN(BZ_DATA_ERROR)  ;
    }                                                                     ;
    ///////////////////////////////////////////////////////////////////////
    s -> cftab [ 0 ] = 0                                                  ;
    for ( i = 1 ; i <= 256 ; i++ ) s->cftab [ i ]  = s->unzftab [ i-1 ]   ;
    for ( i = 1 ; i <= 256 ; i++ ) s->cftab [ i ] += s->cftab   [ i-1 ]   ;
    for ( i = 0 ; i <= 256 ; i++ )                                        {
      if (s->cftab[i] < 0 || s->cftab[i] > nblock)                        {
        RETURN(BZ_DATA_ERROR)                                             ;
      }                                                                   ;
    }                                                                     ;
    ///////////////////////////////////////////////////////////////////////
    for ( i = 1 ; i <= 256 ; i++ )                                        {
      if (s->cftab[i-1] > s->cftab[i])                                    {
        RETURN(BZ_DATA_ERROR)                                             ;
      }                                                                   ;
    }                                                                     ;
    ///////////////////////////////////////////////////////////////////////
    s -> state_out_len = 0                                                ;
    s -> state_out_ch  = 0                                                ;
    BZ_INITIALISE_CRC ( s->calculatedBlockCRC )                           ;
    s->state = BZ_X_OUTPUT                                                ;
    ///////////////////////////////////////////////////////////////////////
    if ( s->smallDecompress )                                             {
      for ( i = 0 ; i <= 256   ; i++ ) s->cftabCopy[i] = s->cftab[i]      ;
      for ( i = 0 ; i < nblock ; i++ )                                    {
        uc = (unsigned char)(s->ll16[i])                                  ;
        SET_LL(i, s->cftabCopy[uc])                                       ;
        s->cftabCopy[uc]++                                                ;
      }                                                                   ;
      /////////////////////////////////////////////////////////////////////
      i = s->origPtr                                                      ;
      j = GET_LL(i)                                                       ;
      do                                                                  {
        int tmp = GET_LL(j)                                               ;
        SET_LL ( j , i )                                                  ;
        i = j                                                             ;
        j = tmp                                                           ;
      } while ( i != s->origPtr )                                         ;
      /////////////////////////////////////////////////////////////////////
      s -> tPos        = s->origPtr                                       ;
      s -> nblock_used = 0                                                ;
      if ( s -> blockRandomised )                                         {
        BZ_RAND_INIT_MASK                                                 ;
        BZ_GET_SMALL(s->k0)                                               ;
        s->nblock_used++                                                  ;
        BZ_RAND_UPD_MASK                                                  ;
        s->k0 ^= BZ_RAND_MASK                                             ;
      } else                                                              {
        BZ_GET_SMALL(s->k0)                                               ;
        s->nblock_used++                                                  ;
      }                                                                   ;
    } else                                                                {
      for (i = 0; i < nblock; i++)                                        {
        uc = (unsigned char)( s->tt[i] & 0xff )                           ;
        s -> tt    [ s -> cftab [ uc ] ] |= (i << 8)                      ;
        s -> cftab [ uc                ] ++                               ;
      }                                                                   ;
      s -> tPos        = s -> tt [ s -> origPtr ] >> 8                    ;
      s -> nblock_used = 0                                                ;
      if ( s -> blockRandomised )                                         {
        BZ_RAND_INIT_MASK                                                 ;
        BZ_GET_FAST(s->k0)                                                ;
        s->nblock_used++                                                  ;
        BZ_RAND_UPD_MASK                                                  ;
        s->k0 ^= BZ_RAND_MASK                                             ;
      } else                                                              {
        BZ_GET_FAST(s->k0)                                                ;
        s->nblock_used++                                                  ;
      }                                                                   ;
    }                                                                     ;
    RETURN ( BZ_OK )                                                      ;
    ///////////////////////////////////////////////////////////////////////
    endhdr_2                                                              :
      GET_UCHAR(BZ_X_ENDHDR_2, uc)                                        ;
      if (uc != 0x72) RETURN(BZ_DATA_ERROR)                               ;
      GET_UCHAR(BZ_X_ENDHDR_3, uc)                                        ;
      if (uc != 0x45) RETURN(BZ_DATA_ERROR)                               ;
      GET_UCHAR(BZ_X_ENDHDR_4, uc)                                        ;
      if (uc != 0x38) RETURN(BZ_DATA_ERROR)                               ;
      GET_UCHAR(BZ_X_ENDHDR_5, uc)                                        ;
      if (uc != 0x50) RETURN(BZ_DATA_ERROR)                               ;
      GET_UCHAR(BZ_X_ENDHDR_6, uc)                                        ;
      if (uc != 0x90) RETURN(BZ_DATA_ERROR)                               ;
      /////////////////////////////////////////////////////////////////////
      s->storedCombinedCRC=0                                              ;
      GET_UCHAR(BZ_X_CCRC_1, uc)                                          ;
      s->storedCombinedCRC=(s->storedCombinedCRC << 8)|((unsigned int)uc) ;
      GET_UCHAR(BZ_X_CCRC_2, uc)                                          ;
      s->storedCombinedCRC=(s->storedCombinedCRC << 8)|((unsigned int)uc) ;
      GET_UCHAR(BZ_X_CCRC_3, uc)                                          ;
      s->storedCombinedCRC=(s->storedCombinedCRC << 8)|((unsigned int)uc) ;
      GET_UCHAR(BZ_X_CCRC_4, uc)                                          ;
      s->storedCombinedCRC=(s->storedCombinedCRC << 8)|((unsigned int)uc) ;
      /////////////////////////////////////////////////////////////////////
      s->state = BZ_X_IDLE                                                ;
      RETURN(BZ_STREAM_END)                                               ;
      default                                                             :
                                                                          ;
  }                                                                       ;
  /////////////////////////////////////////////////////////////////////////
  save_state_and_return                                                   :
    s -> save_i          = i                                              ;
    s -> save_j          = j                                              ;
    s -> save_t          = t                                              ;
    s -> save_alphaSize  = alphaSize                                      ;
    s -> save_nGroups    = nGroups                                        ;
    s -> save_nSelectors = nSelectors                                     ;
    s -> save_EOB        = EOB                                            ;
    s -> save_groupNo    = groupNo                                        ;
    s -> save_groupPos   = groupPos                                       ;
    s -> save_nextSym    = nextSym                                        ;
    s -> save_nblockMAX  = nblockMAX                                      ;
    s -> save_nblock     = nblock                                         ;
    s -> save_es         = es                                             ;
    s -> save_N          = N                                              ;
    s -> save_curr       = curr                                           ;
    s -> save_zt         = zt                                             ;
    s -> save_zn         = zn                                             ;
    s -> save_zvec       = zvec                                           ;
    s -> save_zj         = zj                                             ;
    s -> save_gSel       = gSel                                           ;
    s -> save_gMinlen    = gMinlen                                        ;
    s -> save_gLimit     = gLimit                                         ;
    s -> save_gBase      = gBase                                          ;
    s -> save_gPerm      = gPerm                                          ;
  /////////////////////////////////////////////////////////////////////////
  return retVal                                                           ;
}

int BzCompressInit             (
      BzStream * strm          ,
      int        blockSize100k ,
      int        verbosity     ,
      int        workFactor    )
{
  int      n                                                                 ;
  EState * s = NULL                                                          ;
  ////////////////////////////////////////////////////////////////////////////
  if ( ! bzConfigOk ( ) ) return BZ_CONFIG_ERROR                             ;
  if ( IsNull ( strm       )                                                ||
       (blockSize100k <   1)                                                ||
       (blockSize100k >   9)                                                ||
       (workFactor    <   0)                                                ||
       (workFactor    > 250)                                                 )
    return BZ_PARAM_ERROR                                                    ;
  ////////////////////////////////////////////////////////////////////////////
  if ( workFactor    == 0    ) workFactor    = 30                            ;
  if ( strm->bzalloc == NULL ) strm->bzalloc = defaultBzAlloc                ;
  if ( strm->bzfree  == NULL ) strm->bzfree  = defaultBzFree                 ;
  ////////////////////////////////////////////////////////////////////////////
  s = (EState *)BZALLOC( sizeof(EState) )                                    ;
  if (s == NULL) return BZ_MEM_ERROR                                         ;
  s->strm = strm                                                             ;
  s->arr1 = NULL                                                             ;
  s->arr2 = NULL                                                             ;
  s->ftab = NULL                                                             ;
  n       = 100000 * blockSize100k                                           ;
  s->arr1 = (unsigned int *)BZALLOC(n                 *sizeof(unsigned int)) ;
  s->arr2 = (unsigned int *)BZALLOC((n+BZ_N_OVERSHOOT)*sizeof(unsigned int)) ;
  s->ftab = (unsigned int *)BZALLOC(65537             *sizeof(unsigned int)) ;
  ////////////////////////////////////////////////////////////////////////////
  if ( s->arr1 == NULL || s->arr2 == NULL || s->ftab == NULL )               {
    if ( s->arr1 != NULL ) BZFREE ( s -> arr1 )                              ;
    if ( s->arr2 != NULL ) BZFREE ( s -> arr2 )                              ;
    if ( s->ftab != NULL ) BZFREE ( s -> ftab )                              ;
    if ( s       != NULL ) BZFREE ( s         )                              ;
    return BZ_MEM_ERROR                                                      ;
  }                                                                          ;
  ////////////////////////////////////////////////////////////////////////////
  s    -> blockNo        = 0                                                 ;
  s    -> state          = BZ_S_INPUT                                        ;
  s    -> mode           = BZ_M_RUNNING                                      ;
  s    -> combinedCRC    = 0                                                 ;
  s    -> blockSize100k  = blockSize100k                                     ;
  s    -> nblockMAX      = 100000 * blockSize100k - 19                       ;
  s    -> verbosity      = verbosity                                         ;
  s    -> workFactor     = workFactor                                        ;
  s    -> block          = (unsigned char  *) s -> arr2                      ;
  s    -> mtfv           = (unsigned short *) s -> arr1                      ;
  s    -> zbits          = NULL                                              ;
  s    -> ptr            = (unsigned int *)s->arr1                           ;
  strm -> state          = s                                                 ;
  strm -> total_in_lo32  = 0                                                 ;
  strm -> total_in_hi32  = 0                                                 ;
  strm -> total_out_lo32 = 0                                                 ;
  strm -> total_out_hi32 = 0                                                 ;
  ////////////////////////////////////////////////////////////////////////////
  init_RL           ( s )                                                    ;
  prepare_new_block ( s )                                                    ;
  return BZ_OK                                                               ;
}

static bool BzHandleCompress ( BzStream * strm )
{
  bool     progress_in  = false                                         ;
  bool     progress_out = false                                         ;
  EState * s            = (EState *)strm->state                         ;
  ///////////////////////////////////////////////////////////////////////
  while ( true )                                                        {
    if ( s->state == BZ_S_OUTPUT )                                      {
      progress_out |= copy_output_until_stop ( s )                      ;
      if ( s -> state_out_pos < s->numZ ) break                         ;
      if ( s -> mode            == BZ_M_FINISHING                      &&
           s -> avail_in_expect == 0                                   &&
           isempty_RL ( s ) ) break                                     ;
       prepare_new_block ( s )                                          ;
       s -> state = BZ_S_INPUT                                          ;
       if (s -> mode            == BZ_M_FLUSHING                       &&
           s -> avail_in_expect == 0                                   &&
           isempty_RL ( s ) ) break                                     ;
    }                                                                   ;
    /////////////////////////////////////////////////////////////////////
    if ( s -> state == BZ_S_INPUT )                                     {
      progress_in |= copy_input_until_stop ( s )                        ;
      if ( ( s->mode != BZ_M_RUNNING ) && ( s->avail_in_expect == 0 ) ) {
        flush_RL        ( s                                    )        ;
        BzCompressBlock ( s, (bool)(s->mode == BZ_M_FINISHING) )        ;
        s->state = BZ_S_OUTPUT                                          ;
      } else
      if ( s -> nblock >= s -> nblockMAX )                              {
        BzCompressBlock ( s , false )                                   ;
        s->state = BZ_S_OUTPUT                                          ;
      } else
      if ( s->strm->avail_in == 0 )                                     {
        break                                                           ;
      }                                                                 ;
    }                                                                   ;
  }                                                                     ;
  ///////////////////////////////////////////////////////////////////////
  return ( progress_in || progress_out )                                ;
}

int BzCompress ( BzStream * strm , int action )
{
  bool     progress                                          ;
  EState * s                                                 ;
  if ( strm    == NULL ) return BZ_PARAM_ERROR               ;
  s = (EState *)strm->state                                  ;
  if ( s       == NULL ) return BZ_PARAM_ERROR               ;
  if ( s->strm != strm ) return BZ_PARAM_ERROR               ;
  ////////////////////////////////////////////////////////////
  preswitch                                                  :
  switch ( s -> mode )                                       {
    case BZ_M_IDLE: return BZ_SEQUENCE_ERROR                 ;
    case BZ_M_RUNNING                                        :
      if ( action == BZ_RUN    )                             {
        progress = BzHandleCompress ( strm )                 ;
        return progress ? BZ_RUN_OK : BZ_PARAM_ERROR         ;
      } else
      if ( action == BZ_FLUSH  )                             {
        s->avail_in_expect = strm->avail_in                  ;
        s->mode            = BZ_M_FLUSHING                   ;
        goto preswitch                                       ;
      } else
      if ( action == BZ_FINISH )                             {
        s->avail_in_expect = strm->avail_in                  ;
        s->mode            = BZ_M_FINISHING                  ;
        goto preswitch                                       ;
      } else return BZ_PARAM_ERROR                           ;
    case BZ_M_FLUSHING                                       :
      if (action != BZ_FLUSH) return BZ_SEQUENCE_ERROR       ;
      if (s->avail_in_expect != s->strm->avail_in)           {
        return BZ_SEQUENCE_ERROR                             ;
      }                                                      ;
      progress = BzHandleCompress ( strm )                   ;
      if ((s->avail_in_expect > 0       )                   ||
          !isempty_RL(s)                                    ||
          ( s->state_out_pos < s->numZ) ) return BZ_FLUSH_OK ;
      s->mode = BZ_M_RUNNING                                 ;
    return BZ_RUN_OK                                         ;
    case BZ_M_FINISHING                                      :
      if (action != BZ_FINISH) return BZ_SEQUENCE_ERROR      ;
      if (s->avail_in_expect != s->strm->avail_in)           {
        return BZ_SEQUENCE_ERROR                             ;
      }                                                      ;
      progress = BzHandleCompress ( strm )                   ;
      if (!progress) return BZ_SEQUENCE_ERROR                ;
      if ((s->avail_in_expect > 0    )                      ||
          !isempty_RL(s)                                    ||
          (s->state_out_pos < s->numZ)) return BZ_FINISH_OK  ;
      s->mode = BZ_M_IDLE                                    ;
    return BZ_STREAM_END                                     ;
  }                                                          ;
  return BZ_OK                                               ;
}

int BzCompressEnd ( BzStream * strm )
{
  EState * s                                 ;
  if (strm    == NULL) return BZ_PARAM_ERROR ;
  s = (EState *)( strm -> state )            ;
  if (s       == NULL) return BZ_PARAM_ERROR ;
  if (s->strm != strm) return BZ_PARAM_ERROR ;
  if (s->arr1 != NULL) BZFREE(s->arr1)       ;
  if (s->arr2 != NULL) BZFREE(s->arr2)       ;
  if (s->ftab != NULL) BZFREE(s->ftab)       ;
  BZFREE(strm->state)                        ;
  strm->state = NULL                         ;
  return BZ_OK                               ;
}

int BzDecompressInit       (
      BzStream * strm      ,
      int        verbosity ,
      int        Small     )
{
  DState * s                                                  ;
  if ( !bzConfigOk()                 ) return BZ_CONFIG_ERROR ;
  if ( strm == NULL                  ) return BZ_PARAM_ERROR  ;
  if ( Small    != 0 && Small    != 1) return BZ_PARAM_ERROR  ;
  if ( verbosity < 0 || verbosity > 4) return BZ_PARAM_ERROR  ;
  if ( strm->bzalloc == NULL ) strm->bzalloc = defaultBzAlloc ;
  if ( strm->bzfree  == NULL ) strm->bzfree  = defaultBzFree  ;
  s = (DState *) BZALLOC ( sizeof(DState) )                   ;
  if (s == NULL) return BZ_MEM_ERROR                          ;
  /////////////////////////////////////////////////////////////
  s    -> strm                  = strm                        ;
  strm -> state                 = s                           ;
  s    -> state                 = BZ_X_MAGIC_1                ;
  s    -> bsLive                = 0                           ;
  s    -> bsBuff                = 0                           ;
  s    -> calculatedCombinedCRC = 0                           ;
  strm -> total_in_lo32         = 0                           ;
  strm -> total_in_hi32         = 0                           ;
  strm -> total_out_lo32        = 0                           ;
  strm -> total_out_hi32        = 0                           ;
  s    -> smallDecompress       = (bool)Small                 ;
  s    -> ll4                   = NULL                        ;
  s    -> ll16                  = NULL                        ;
  s    -> tt                    = NULL                        ;
  s    -> currBlockNo           = 0                           ;
  s    -> verbosity             = verbosity                   ;
  return BZ_OK                                                ;
}

int BzDecompress ( BzStream * strm )
{
  bool     corrupt                                            ;
  DState * s                                                  ;
  /////////////////////////////////////////////////////////////
  if ( strm      == NULL ) return BZ_PARAM_ERROR              ;
  s = (DState *)strm->state                                   ;
  if ( s         == NULL ) return BZ_PARAM_ERROR              ;
  if ( s -> strm != strm ) return BZ_PARAM_ERROR              ;
  /////////////////////////////////////////////////////////////
  while ( true )                                              {
    if ( s->state == BZ_X_IDLE   ) return BZ_SEQUENCE_ERROR   ;
    if ( s->state == BZ_X_OUTPUT )                            {
      if ( s->smallDecompress )                               {
        corrupt = unRLE_obuf_to_output_SMALL ( s )            ;
      } else                                                  {
        corrupt = unRLE_obuf_to_output_FAST  ( s )            ;
      }                                                       ;
      if (corrupt) return BZ_DATA_ERROR                       ;
      if (s -> nblock_used   == ( s->save_nblock + 1 )       &&
          s -> state_out_len == 0                           ) {
        BZ_FINALISE_CRC ( s->calculatedBlockCRC )             ;
        if (s->calculatedBlockCRC != s->storedBlockCRC)       {
          return BZ_DATA_ERROR                                ;
        }                                                     ;
        s -> calculatedCombinedCRC                            =
          ( s -> calculatedCombinedCRC <<  1)                 |
          ( s -> calculatedCombinedCRC >> 31)                 ;
        s -> calculatedCombinedCRC ^= s->calculatedBlockCRC   ;
        s -> state                  = BZ_X_BLKHDR_1           ;
      } else return BZ_OK                                     ;
    }                                                         ;
    if ( s->state >= BZ_X_MAGIC_1 )                           {
      int r = BzDecompress ( s )                              ;
      if ( r == BZ_STREAM_END )                               {
        if (s->calculatedCombinedCRC != s->storedCombinedCRC) {
          return BZ_DATA_ERROR                                ;
        }                                                     ;
        return r                                              ;
      }                                                       ;
      if (s->state != BZ_X_OUTPUT) return r                   ;
    }                                                         ;
  }                                                           ;
  return 0                                                    ;
}

int BzDecompressEnd ( BzStream * strm )
{
  DState * s                                   ;
  if ( strm    == NULL ) return BZ_PARAM_ERROR ;
  s = (DState *)strm->state                    ;
  if ( s       == NULL ) return BZ_PARAM_ERROR ;
  if ( s->strm != strm ) return BZ_PARAM_ERROR ;
  if ( s->tt   != NULL ) BZFREE ( s->tt   )    ;
  if ( s->ll16 != NULL ) BZFREE ( s->ll16 )    ;
  if ( s->ll4  != NULL ) BZFREE ( s->ll4  )    ;
  BZFREE ( strm->state )                       ;
  strm->state = NULL                           ;
  return BZ_OK                                 ;
}

int BzBuffToBuffCompress           (
      char         * dest          ,
      unsigned int * destLen       ,
      char         * source        ,
      unsigned int   sourceLen     ,
      int            blockSize100k ,
      int            verbosity     ,
      int            workFactor    )
{
  BzStream strm                                  ;
  int      ret                                   ;
  ////////////////////////////////////////////////
  if (dest          == NULL                     ||
      destLen       == NULL                     ||
      source        == NULL                     ||
      blockSize100k  < 1                        ||
      blockSize100k  > 9                        ||
      verbosity      < 0                        ||
      verbosity      > 4                        ||
      workFactor     < 0                        ||
      workFactor     > 250                       )
    return BZ_PARAM_ERROR                        ;
  ////////////////////////////////////////////////
  if (workFactor == 0) workFactor = 30           ;
  strm . bzalloc = NULL                          ;
  strm . bzfree  = NULL                          ;
  strm . opaque  = NULL                          ;
  ret = BzCompressInit                           (
    &strm                                        ,
    blockSize100k                                ,
    verbosity                                    ,
    workFactor                                 ) ;
  if (ret != BZ_OK) return ret                   ;
  ////////////////////////////////////////////////
  strm . next_in   =   source                    ;
  strm . next_out  =   dest                      ;
  strm . avail_in  =   sourceLen                 ;
  strm . avail_out = * destLen                   ;
  ////////////////////////////////////////////////
  ret = BzCompress ( &strm,BZ_FINISH )           ;
  if (ret == BZ_FINISH_OK ) goto output_overflow ;
  if (ret != BZ_STREAM_END) goto errhandler      ;
  ////////////////////////////////////////////////
  *destLen -= strm.avail_out                     ;
  BzCompressEnd ( &strm )                        ;
  return BZ_OK                                   ;
  ////////////////////////////////////////////////
  output_overflow                                :
  BzCompressEnd ( &strm )                        ;
  return BZ_OUTBUFF_FULL                         ;
  ////////////////////////////////////////////////
  errhandler                                     :
  BzCompressEnd ( &strm )                        ;
  return ret                                     ;
}

int BzBuffToBuffDecompress     (
      char         * dest      ,
      unsigned int * destLen   ,
      char         * source    ,
      unsigned int   sourceLen ,
      int            Small     ,
      int            verbosity )
{
  BzStream strm                                         ;
  int      ret                                          ;
  ///////////////////////////////////////////////////////
  if (dest    == NULL                                  ||
      destLen == NULL                                  ||
      source  == NULL                                  ||
      (Small != 0 && Small != 1)                       ||
      verbosity < 0                                    ||
      verbosity > 4                                     )
    return BZ_PARAM_ERROR                               ;
  ///////////////////////////////////////////////////////
  strm . bzalloc = NULL                                 ;
  strm . bzfree  = NULL                                 ;
  strm . opaque  = NULL                                 ;
  ret  = BzDecompressInit                               (
           &strm                                        ,
           verbosity                                    ,
           Small                                      ) ;
  if (ret != BZ_OK) return ret                          ;
  ///////////////////////////////////////////////////////
  strm . next_in   =   source                           ;
  strm . next_out  =   dest                             ;
  strm . avail_in  =   sourceLen                        ;
  strm . avail_out = * destLen                          ;
  ///////////////////////////////////////////////////////
  ret = BzDecompress ( &strm )                          ;
  if (ret == BZ_OK        ) goto output_overflow_or_eof ;
  if (ret != BZ_STREAM_END) goto errhandler             ;
  ///////////////////////////////////////////////////////
  *destLen -= strm.avail_out                            ;
  BzDecompressEnd ( &strm )                             ;
  return BZ_OK                                          ;
  ///////////////////////////////////////////////////////
  output_overflow_or_eof                                :
  if (strm.avail_out > 0)                               {
    BzDecompressEnd ( &strm )                           ;
    return BZ_UNEXPECTED_EOF                            ;
  } else                                                {
    BzDecompressEnd ( &strm )                           ;
    return BZ_OUTBUFF_FULL                              ;
  }                                                     ;
  ///////////////////////////////////////////////////////
  errhandler                                            :
  BzDecompressEnd ( &strm )                             ;
  return ret                                            ;
}

//////////////////////////////////////////////////////////////////////////////

void BZip2CRC(const QByteArray & Data,unsigned int & bcrc)
{
  if (Data.size()<=0) return                       ;
  int s = Data.size()                              ;
  unsigned char * d = (unsigned char *)Data.data() ;
  for (int i=0;i<s;i++)                            {
    BZ_UPDATE_CRC(bcrc,d[i])                       ;
  }                                                ;
}

void BZip2CRC(int length,const QByteArray & Data,unsigned int & bcrc)
{
  if (length<=0) return                            ;
  int s = length                                   ;
  unsigned char * d = (unsigned char *)Data.data() ;
  for (int i=0;i<s;i++)                            {
    BZ_UPDATE_CRC(bcrc,d[i])                       ;
  }                                                ;
}

//////////////////////////////////////////////////////////////////////////////

QtBZip2:: QtBZip2  (void)
        : BzPacket (NULL)
{
}

QtBZip2::~QtBZip2(void)
{
  CleanUp ( ) ;
}

QString QtBZip2::Version(void)
{
  return QString ( "1.0.6" ) ;
}

bool QtBZip2::isBZip2(QByteArray & header)
{
  if (header.size()<4) return false ;
  char * h = (char *)header.data()  ;
  if (h[0]!='B') return false       ;
  if (h[1]!='Z') return false       ;
  bool zd = false                   ;
  if (h[2]=='h') zd = true          ;
  if (h[2]=='0') zd = true          ;
  if (!zd      ) return false       ;
  if (h[3] <'1') return false       ;
  if (h[3] >'9') return false       ;
  return true                       ;
}

void QtBZip2::CleanUp(void)
{
  if ( IsNull(BzPacket) ) return     ;
//  BzFile * bzf = (BzFile *) BzPacket ;
  ////////////////////////////////////

  ////////////////////////////////////
  ::free(BzPacket)                   ;
  BzPacket = NULL                    ;
}

bool QtBZip2::IsCorrect(int returnCode)
{
  if ( returnCode == BZ_OK         ) return true ;
  if ( returnCode == BZ_STREAM_END ) return true ;
  return false                                   ;
}

bool QtBZip2::IsEnd(int returnCode)
{
  return ( returnCode == BZ_STREAM_END ) ;
}

bool QtBZip2::IsFault(int returnCode)
{
  return ( returnCode < 0 ) ;
}

int QtBZip2::BeginCompress(int blockSize100k,int workFactor)
{
  int      ret                                    ;
  BzFile * bzf = NULL                             ;
  /////////////////////////////////////////////////
  if ( ( workFactor < 0 ) || (workFactor > 250)   )
    return BZ_PARAM_ERROR                         ;
  if (blockSize100k < 1) blockSize100k = 1        ;
  if (blockSize100k > 9) blockSize100k = 9        ;
  /////////////////////////////////////////////////
  bzf = (BzFile *)::malloc(sizeof(BzFile))        ;
  if (IsNull(bzf)) return BZ_MEM_ERROR            ;
  /////////////////////////////////////////////////
  ::memset ( bzf , 0 , sizeof(BzFile) )           ;
  bzf->bufferSize    = 0                          ;
  bzf->Writing       = true                       ;
  bzf->LastError     = BZ_OK                      ;
  bzf->InitialisedOk = false                      ;
  bzf->Strm.bzalloc  = NULL                       ;
  bzf->Strm.bzfree   = NULL                       ;
  bzf->Strm.opaque   = NULL                       ;
  /////////////////////////////////////////////////
  if (workFactor == 0) workFactor = 30            ;
  /////////////////////////////////////////////////
  ret = BzCompressInit                            (
          &(bzf->Strm)                            ,
          blockSize100k                           ,
          1                                       ,
          workFactor                            ) ;
  /////////////////////////////////////////////////
  if ( ret != BZ_OK)                              {
    ::free(bzf)                                   ;
    return ret                                    ;
  }                                               ;
  /////////////////////////////////////////////////
  bzf     -> Strm.avail_in = 0                    ;
  bzf     -> InitialisedOk = true                 ;
  BZ_INITIALISE_CRC(bzf->CRC32)                   ;
  /////////////////////////////////////////////////
  BzPacket = bzf                                  ;
  return BZ_OK                                    ;
}

int QtBZip2::BeginCompress(QVariantList arguments)
{
  int blockSize100k =  9                                        ;
  int workFactor    = 30                                        ;
  if (arguments.count()>0) blockSize100k = arguments[0].toInt() ;
  if (arguments.count()>1) workFactor    = arguments[1].toInt() ;
  return BeginCompress ( blockSize100k , workFactor )           ;
}

int QtBZip2::doCompress(const QByteArray & Source,QByteArray & Compressed)
{
  if (IsNull(BzPacket)) return BZ_MEM_ERROR    ;
  int      n, ret                              ;
  BzFile * bzf = (BzFile *)BzPacket            ;
  //////////////////////////////////////////////
  if (!bzf->Writing) return BZ_SEQUENCE_ERROR  ;
  //////////////////////////////////////////////
  Compressed . clear ( )                       ;
  ret = BZ_OK                                  ;
  if (Source.size()<=0) return BZ_OK           ;
  //////////////////////////////////////////////
  bzf->Strm.avail_in =         Source . size() ;
  bzf->Strm.next_in  = (char *)Source . data() ;
  //////////////////////////////////////////////
  while ( true )                               {
    bzf->Strm.avail_out = BZ_MAX_UNUSED        ;
    bzf->Strm.next_out  = bzf->buffer          ;
    ret = BzCompress ( &(bzf->Strm), BZ_RUN )  ;
    if (ret != BZ_RUN_OK) return ret           ;
    if (bzf->Strm.avail_out < BZ_MAX_UNUSED)   {
      n  = BZ_MAX_UNUSED - bzf->Strm.avail_out ;
      if (n>0)                                 {
        Compressed.append(bzf->buffer,n)       ;
      }                                        ;
    }                                          ;
    if (bzf->Strm.avail_in == 0) return BZ_OK  ;
  }                                            ;
  //////////////////////////////////////////////
  return BZ_DATA_ERROR                         ;
}

int QtBZip2::doSection(QByteArray & Source,QByteArray & Compressed)
{
  if (IsNull(BzPacket)) return BZ_MEM_ERROR      ;
  int      n, ret                                ;
  BzFile * bzf = (BzFile *)BzPacket              ;
  ////////////////////////////////////////////////
  if (!bzf->Writing) return BZ_SEQUENCE_ERROR    ;
  ////////////////////////////////////////////////
  Compressed . clear ( )                         ;
  ret = BZ_OK                                    ;
  if (Source.size()<=0) return BZ_OK             ;
  ////////////////////////////////////////////////
  if (Source.size()>BZ_MAX_UNUSED)               {
    n                  = BZ_MAX_UNUSED           ;
    bzf->bufferSize    = n                       ;
    bzf->Strm.avail_in = n                       ;
    bzf->Strm.next_in  = (char *)Source . data() ;
  } else                                         {
    n                  = Source.size()           ;
    bzf->bufferSize    = n                       ;
    bzf->Strm.avail_in = n                       ;
    bzf->Strm.next_in  = bzf->unused             ;
    ::memset ( bzf->unused , 0 , BZ_MAX_UNUSED ) ;
    ::memcpy ( bzf->unused , Source.data() , n ) ;
  }                                              ;
  ////////////////////////////////////////////////
  bzf->Strm.avail_out = BZ_MAX_UNUSED            ;
  bzf->Strm.next_out  = bzf->buffer              ;
  ////////////////////////////////////////////////
  ret = BzCompress ( &(bzf->Strm), BZ_RUN )      ;
  n = ( bzf->bufferSize - bzf->Strm.avail_in )   ;
  if (n>0)                                       {
    BZip2CRC ( n , Source , bzf->CRC32 )         ;
    Source.remove(0,n)                           ;
  }                                              ;
  if (ret != BZ_RUN_OK) return ret               ;
  if (bzf->Strm.avail_out < BZ_MAX_UNUSED)       {
    n = BZ_MAX_UNUSED - bzf->Strm.avail_out      ;
    if (n>0)                                     {
      Compressed.append(bzf->buffer,n)           ;
    }                                            ;
    return BZ_OK                                 ;
  }                                              ;
  if (bzf->Strm.avail_in == 0) return BZ_OK      ;
  ////////////////////////////////////////////////
  return BZ_DATA_ERROR                           ;
}

int QtBZip2::CompressDone(QByteArray & Compressed)
{
  int      n, ret                                            ;
  BzFile * bzf = (BzFile*)BzPacket                           ;
  if ( IsNull(bzf)   ) return BZ_OK                          ;
  if ( !bzf->Writing ) return BZ_SEQUENCE_ERROR              ;
  ////////////////////////////////////////////////////////////
  if (bzf->LastError == BZ_OK)                               {
    while ( true )                                           {
      bzf -> Strm.avail_in  = 0                              ;
      bzf -> Strm.next_in   = bzf->unused                    ;
      bzf -> Strm.avail_out = BZ_MAX_UNUSED                  ;
      bzf -> Strm.next_out  = bzf->buffer                    ;
      ret  = BzCompress ( &(bzf->Strm), BZ_FINISH )          ;
      if ( ( ret!=BZ_FINISH_OK ) && ( ret!=BZ_STREAM_END ) ) {
        return ret                                           ;
      }                                                      ;
      ////////////////////////////////////////////////////////
      if ( bzf -> Strm.avail_out < BZ_MAX_UNUSED)            {
        n  = BZ_MAX_UNUSED - bzf->Strm.avail_out             ;
        if (n>0)                                             {
          Compressed.append(bzf->buffer,n)                   ;
        } else break                                         ;
      }                                                      ;
    }                                                        ;
  }                                                          ;
  ////////////////////////////////////////////////////////////
  BzCompressEnd ( &(bzf->Strm) )                             ;
  return BZ_OK                                               ;
}

int QtBZip2::BeginDecompress(void)
{
  BzFile * bzf     = NULL                         ;
  int      ret     = BZ_OK                        ;
  int      Small   = 0                            ;
  /////////////////////////////////////////////////
  bzf = (BzFile *)::malloc(sizeof(BzFile))        ;
  if (IsNull(bzf)) return BZ_MEM_ERROR            ;
  /////////////////////////////////////////////////
  memset ( bzf , 0 , sizeof(BzFile) )             ;
  bzf->bufferSize    = 0                          ;
  bzf->Writing       = false                      ;
  bzf->LastError     = BZ_OK                      ;
  bzf->InitialisedOk = false                      ;
  bzf->Strm.bzalloc  = NULL                       ;
  bzf->Strm.bzfree   = NULL                       ;
  bzf->Strm.opaque   = NULL                       ;
  /////////////////////////////////////////////////
  ret = BzDecompressInit ( &(bzf->Strm),1,Small ) ;
  /////////////////////////////////////////////////
  if ( ret != BZ_OK)                              {
    ::free(bzf)                                   ;
    return ret                                    ;
  }                                               ;
  /////////////////////////////////////////////////
  bzf -> Strm.avail_in = bzf->bufferSize          ;
  bzf -> Strm.next_in  = bzf->buffer              ;
  bzf -> InitialisedOk = true                     ;
  BZ_INITIALISE_CRC(bzf->CRC32)                   ;
  /////////////////////////////////////////////////
  BzPacket = bzf                                  ;
  return BZ_OK                                    ;
}

int QtBZip2::doDecompress(const QByteArray & Source,QByteArray & Decompressed)
{
  int      n                                              ;
  int      ret = BZ_OK                                    ;
  BzFile * bzf = (BzFile*)BzPacket                        ;
  if ( IsNull(bzf)  ) return BZ_OK                        ;
  if ( bzf->Writing ) return BZ_SEQUENCE_ERROR            ;
  /////////////////////////////////////////////////////////
  if ( bzf->LastError == BZ_STREAM_END)                   {
    Decompressed . clear ( )                              ;
    return BZ_STREAM_END                                  ;
  }                                                       ;
  /////////////////////////////////////////////////////////
  bzf->LastError = BZ_OK                                  ;
  ret            = BZ_OK                                  ;
  if (Source.size()<=0)                                   {
    Decompressed . clear ( )                              ;
    return BZ_STREAM_END                                  ;
  }                                                       ;
  /////////////////////////////////////////////////////////
  char * src = (char *)Source.data()                      ;
  int    idx = 0                                          ;
  while ( true )                                          {
    if ( bzf->Strm.avail_in == 0 )                        {
      if ( ( Source.size() - idx ) > BZ_MAX_UNUSED )      {
        n = BZ_MAX_UNUSED                                 ;
      } else                                              {
        n = Source.size() - idx                           ;
      }                                                   ;
      ::memcpy ( bzf->buffer , src , n )                  ;
      src += n                                            ;
      idx += n                                            ;
      /////////////////////////////////////////////////////
      bzf->bufferSize    = n                              ;
      bzf->Strm.avail_in = bzf->bufferSize                ;
      bzf->Strm.next_in  = bzf->buffer                    ;
    }                                                     ;
    bzf -> Strm.avail_out = BZ_MAX_UNUSED                 ;
    bzf -> Strm.next_out  = bzf->unused                   ;
    ///////////////////////////////////////////////////////
    ret = BzDecompress ( &(bzf->Strm) )                   ;
    if ( ( ret != BZ_OK ) && ( ret != BZ_STREAM_END ) )   {
      return ret                                          ;
    }                                                     ;
    ///////////////////////////////////////////////////////
    if (ret == BZ_OK                                     &&
        bzf -> Strm.avail_in == 0                        &&
        bzf -> Strm.avail_out > 0 )                       {
      n = BZ_MAX_UNUSED - bzf->Strm.avail_out             ;
      if (n==0) Decompressed . clear  (   ) ; else        {
        Decompressed . append ( bzf->buffer , n )         ;
      }                                                   ;
      bzf->LastError = BZ_OK                              ;
      return BZ_OK                                        ;
    }                                                     ;
    if (ret == BZ_STREAM_END)                             {
      n = BZ_MAX_UNUSED - bzf->Strm.avail_out             ;
      if (n==0) Decompressed . clear  (   ) ; else        {
        Decompressed . append ( bzf->buffer , n )         ;
      }                                                   ;
      bzf->LastError = BZ_STREAM_END                      ;
      return BZ_STREAM_END                                ;
    }                                                     ;
    if (bzf->Strm.avail_out == 0)                         {
      if (ret == BZ_OK)                                   {
        n = BZ_MAX_UNUSED                                 ;
        Decompressed.append ((const char *)bzf->buffer,n) ;
        idx += (bzf->bufferSize - bzf->Strm.avail_in)     ;
        bzf->Strm.avail_in = 0                            ;
      } else                                              {
        Decompressed . clear ( )                          ;
        bzf->LastError = BZ_OK                            ;
        return BZ_OK                                      ;
      }                                                   ;
    }                                                     ;
  }                                                       ;
  /////////////////////////////////////////////////////////
  return BZ_OK                                            ;
}

int QtBZip2::undoSection(QByteArray & Source,QByteArray & Decompressed)
{
  int      n                                            ;
  int      ret = BZ_OK                                  ;
  BzFile * bzf = (BzFile*)BzPacket                      ;
  if ( IsNull(bzf)  ) return BZ_OK                      ;
  if ( bzf->Writing ) return BZ_SEQUENCE_ERROR          ;
  ///////////////////////////////////////////////////////
  if ( bzf->LastError == BZ_STREAM_END)                 {
    Decompressed . clear ( )                            ;
    return BZ_STREAM_END                                ;
  }                                                     ;
  ///////////////////////////////////////////////////////
  bzf->LastError = BZ_OK                                ;
  ret            = BZ_OK                                ;
  ///////////////////////////////////////////////////////
  bzf -> Strm.avail_out = BZ_MAX_UNUSED                 ;
  bzf -> Strm.next_out  = bzf->unused                   ;
  ///////////////////////////////////////////////////////
  if (Source.size()<=0)                                 {
    bzf->bufferSize    = 0                              ;
    bzf->Strm.avail_in = 0                              ;
    bzf->Strm.next_in  = NULL                           ;
  } else                                                {
    char * src = (char *)Source.data()                  ;
    if ( Source.size() > BZ_MAX_UNUSED )                {
      n = BZ_MAX_UNUSED                                 ;
    } else                                              {
      n = Source.size()                                 ;
    }                                                   ;
    ::memcpy ( bzf -> buffer , src , n )                ;
    bzf->bufferSize    = n                              ;
    bzf->Strm.avail_in = n                              ;
    bzf->Strm.next_in  = bzf->buffer                    ;
  }                                                     ;
  ///////////////////////////////////////////////////////
  ret = BzDecompress ( &(bzf->Strm) )                   ;
  if ( ( ret != BZ_OK ) && ( ret != BZ_STREAM_END ) )   {
    return ret                                          ;
  }                                                     ;
  ///////////////////////////////////////////////////////
  n = ( bzf->bufferSize - bzf->Strm.avail_in )          ;
  if (n>0) Source.remove(0,n)                           ;
  ///////////////////////////////////////////////////////
  if (ret == BZ_OK                                     &&
      bzf -> Strm.avail_in == 0                        &&
      bzf -> Strm.avail_out > 0 )                       {
    n = BZ_MAX_UNUSED - bzf->Strm.avail_out             ;
    if (n==0) Decompressed . clear  (   ) ; else        {
      Decompressed . append ( bzf->unused , n )         ;
      BZip2CRC ( Decompressed , bzf->CRC32 )            ;
    }                                                   ;
    bzf->LastError = BZ_OK                              ;
    return BZ_OK                                        ;
  }                                                     ;
  if (ret == BZ_STREAM_END)                             {
    n = BZ_MAX_UNUSED - bzf->Strm.avail_out             ;
    if (n==0) Decompressed . clear  (   ) ; else        {
      Decompressed . append ( bzf->unused , n )         ;
      BZip2CRC ( Decompressed , bzf->CRC32 )            ;
    }                                                   ;
    bzf->LastError = BZ_STREAM_END                      ;
    return BZ_STREAM_END                                ;
  }                                                     ;
  if (bzf->Strm.avail_out == 0)                         {
    if (ret == BZ_OK)                                   {
      n = BZ_MAX_UNUSED                                 ;
      Decompressed.append ((const char *)bzf->unused,n) ;
      BZip2CRC ( Decompressed , bzf->CRC32 )            ;
      bzf->Strm.avail_in = 0                            ;
    } else                                              {
      Decompressed . clear ( )                          ;
      bzf->LastError = BZ_OK                            ;
      return BZ_OK                                      ;
    }                                                   ;
  }                                                     ;
  return BZ_OK                                          ;
}

int QtBZip2::DecompressDone(void)
{
  BzFile * bzf = (BzFile*)BzPacket             ;
  if ( IsNull(bzf)  ) return BZ_OK             ;
  if ( bzf->Writing ) return BZ_SEQUENCE_ERROR ;
  //////////////////////////////////////////////
  if ( bzf->InitialisedOk)                     {
    ::BzDecompressEnd ( &(bzf->Strm) )         ;
  }                                            ;
  return BZ_OK                                 ;
}

bool QtBZip2::IsTail(QByteArray & header)
{
  if (header.size()<10)                                      {
    QString    MC                                            ;
    MC = QString ( "BZIP2 trailer less than 10 bytes : %1"   )
         .arg    ( header.size()                           ) ;
    DebugInfo [ "Trailer" ] = MC                             ;
    return false                                             ;
  }                                                          ;
  BzFile * bzf = (BzFile*)BzPacket                           ;
  if ( IsNull(bzf)  ) return false                           ;
  bool correct = true                                        ;
  unsigned char * e = (unsigned char *)header.data()         ;
  if (e[0]!=0x17) correct = false                            ;
  if (e[1]!=0x72) correct = false                            ;
  if (e[2]!=0x45) correct = false                            ;
  if (e[3]!=0x38) correct = false                            ;
  if (e[4]!=0x50) correct = false                            ;
  if (e[5]!=0x90) correct = false                            ;
  if (!correct)                                              {
    QByteArray OC((const char *)e,6)                         ;
    QString    MC                                            ;
    OC = OC.toHex()                                          ;
    MC = QString ( "Incorrect BZIP2 trailer : %1 , %2 bytes" )
         .arg    ( QString::fromUtf8(OC)                     )
         .arg    ( header.size()                           ) ;
    DebugInfo [ "Error" ] = MC                               ;
  }                                                          ;
  e += 6                                                     ;
  unsigned int   ocrc = 0                                    ;
  unsigned int   bcrc = bzf->CRC32                           ;
  BZ_FINALISE_CRC(bcrc)                                      ;
  ocrc   = e[0] ; ocrc <<= 8                                 ;
  ocrc  |= e[1] ; ocrc <<= 8                                 ;
  ocrc  |= e[2] ; ocrc <<= 8                                 ;
  ocrc  |= e[3]                                              ;
  if (ocrc!=bcrc)                                            {
    QByteArray OC((const char *)&ocrc,4)                     ;
    QByteArray BC((const char *)&bcrc,4)                     ;
    QString    MC                                            ;
    OC = OC.toHex()                                          ;
    BC = BC.toHex()                                          ;
    MC = QString ( "CRC does not match : %1 != %2"           )
        .arg ( QString::fromUtf8(OC)                         )
        .arg ( QString::fromUtf8(BC)                       ) ;
    DebugInfo [ "CRC" ] = MC                                 ;
    correct = false                                          ;
  }                                                          ;
  header.remove(0,10)                                        ;
  return correct                                             ;
}

bool QtBZip2::CompressHeader(QByteArray & header)
{
  Q_UNUSED(header);
//  char BZH[5] = { 'B' , 'Z' , 'h' , '9' , 0 } ;
//  header . append ( BZH , 4 )                 ;
  return true                                 ;
}

bool QtBZip2::CompressTail(QByteArray & header)
{
  BzFile * bzf = (BzFile*)BzPacket                                   ;
  if ( IsNull(bzf)  ) return false                                   ;
  unsigned char EOS[6] = { 0x17 , 0x72 , 0x45 , 0x38 , 0x50 , 0x90 } ;
  header.append((const char *)EOS,6)                                 ;
  header.append((const char *)&(bzf->CRC32),4)                       ;
  return true                                                        ;
}

//////////////////////////////////////////////////////////////////////////////

QByteArray BZip2Compress(const QByteArray & data,int level)
{
  QByteArray    Body                       ;
  if (data.size()<=0) return Body          ;
  unsigned int sourceLength = data.size()  ;
  unsigned int destLength   = 0            ;
  unsigned int bufferLength = sourceLength ;
  bufferLength += (bufferLength / 50)      ;
  bufferLength += 1024                     ;
  if (bufferLength<4096)                   {
    bufferLength = 4096                    ;
  }                                        ;
  char * buffer = new char[bufferLength]   ;
  destLength = bufferLength                ;
  if (BZ_OK==::BzBuffToBuffCompress        (
               buffer                      ,
               &destLength                 ,
               (char*)data.data()          ,
               sourceLength                ,
               level,0,0               ) ) {
    if (destLength>0)                      {
      Body.append(buffer,destLength)       ;
    }                                      ;
  }                                        ;
  delete [ ] buffer                        ;
  return Body                              ;
}

//////////////////////////////////////////////////////////////////////////////

QByteArray BZip2Uncompress(const QByteArray & data)
{
  QByteArray    Body                          ;
  if (data.size()<=0) return Body             ;
  BzStream      BS                            ;
  unsigned char BUF    [256*1024]             ;
  int           Size  = 256*1024              ;
  int           Ssize = Size / 64             ;
  int           index = 0                     ;
  int           total = data.size()           ;
  bool          done  = false                 ;
  char        * in    = (char *)data.data()   ;
  int           length                        ;
  int           compr                         ;
  int           rtcode                        ;
  rtcode = ::BzDecompressInit ( &BS , 0 , 0 ) ;
  if (NotEqual(rtcode,BZ_OK)) return Body     ;
  while (!done)                               {
    BS.next_in    = &in[index]                ;
    BS.avail_in   = Ssize                     ;
    if ((total-index)<(int)BS.avail_in)       {
      BS.avail_in = (total-index)             ;
    }                                         ;
    BS.next_out   = (char *)BUF               ;
    BS.avail_out  = Size                      ;
    compr         = BS.avail_in               ;
    rtcode = ::BzDecompress ( &BS )           ;
    if (rtcode==BZ_STREAM_END)                {
      done   = true                           ;
      compr  = compr - BS.avail_in            ;
      length = Size     - BS.avail_out        ;
      if (length>0)                           {
        Body.append((const char *)BUF,length) ;
      }                                       ;
    } else                                    {
      compr  = compr - BS.avail_in            ;
      length = Size  - BS.avail_out           ;
      Body.append((const char *)BUF,length)   ;
    }                                         ;
    index        += compr                     ;
    if (index>=total) done = true             ;
  }                                           ;
  ::BzDecompressEnd ( &BS )                   ;
  return Body                                 ;
}

//////////////////////////////////////////////////////////////////////////////

bool ToBZip2(const QByteArray & data,QByteArray & bzip2,int level,int workFactor)
{
  if ( data . size ( ) <= 0 ) return false ;
  //////////////////////////////////////////
  QtBZip2      L                           ;
  int          r                           ;
  QVariantList v                           ;
  v << level                               ;
  v << workFactor                          ;
  r = L . BeginCompress ( v )              ;
  if ( L . IsCorrect ( r ) )               {
    L . doCompress   ( data , bzip2 )      ;
    L . CompressDone (        bzip2 )      ;
  }                                        ;
  //////////////////////////////////////////
  return ( bzip2 . size ( ) > 0 )          ;
}

//////////////////////////////////////////////////////////////////////////////

bool FromBZip2(const QByteArray & bzip2,QByteArray & data)
{
  if ( bzip2 . size ( ) <= 0 ) return false ;
  ///////////////////////////////////////////
  QtBZip2 L                                 ;
  int     r                                 ;
  r = L . BeginDecompress ( )               ;
  if ( L . IsCorrect ( r ) )                {
    L . doDecompress   ( bzip2 , data )     ;
    L . DecompressDone (              )     ;
  }                                         ;
  ///////////////////////////////////////////
  return ( data . size ( ) > 0 )            ;
}

//////////////////////////////////////////////////////////////////////////////

bool SaveBZip2 (QString filename,QByteArray & data,int level,int workFactor)
{
  if ( data . size ( ) <= 0 ) return false                            ;
  QByteArray bzip2                                                    ;
  if ( level < 0 ) level = 9                                          ;
  if ( ! ToBZip2 ( data , bzip2 , level , workFactor ) ) return false ;
  if ( bzip2 . size ( ) <= 0                     ) return false       ;
  QFile F ( filename )                                                ;
  if ( ! F . open ( QIODevice::WriteOnly | QIODevice::Truncate ) )    {
    return false                                                      ;
  }                                                                   ;
  F . write ( bzip2 )                                                 ;
  F . close (     )                                                   ;
  return true                                                         ;
}

//////////////////////////////////////////////////////////////////////////////

bool LoadBZip2 (QString filename,QByteArray & data)
{
  QFile F ( filename )                                   ;
  if ( ! F . open ( QIODevice::ReadOnly ) ) return false ;
  QByteArray bzip2                                       ;
  bzip2 = F . readAll ( )                                ;
  F . close         ( )                                  ;
  if ( bzip2 . size ( ) <= 0 ) return false              ;
  if ( ! FromBZip2 ( bzip2 , data ) ) return false       ;
  return ( data . size ( ) > 0 )                         ;
}

//////////////////////////////////////////////////////////////////////////////

bool FileToBZip2(QString filename,QString bzip2,int level,int workFactor)
{
  QFile F ( filename )                                   ;
  if ( ! F . open ( QIODevice::ReadOnly ) ) return false ;
  QByteArray data                                        ;
  data = F . readAll ( )                                 ;
  F . close ( )                                          ;
  if ( data . size ( ) <= 0 ) return false               ;
  return SaveBZip2 ( bzip2 , data , level , workFactor ) ;
}

//////////////////////////////////////////////////////////////////////////////

bool BZip2ToFile(QString bzip2,QString filename)
{
  QByteArray data                                        ;
  if ( ! LoadBZip2 ( bzip2 , data ) ) return false       ;
  if ( data . size ( ) <=0      ) return false           ;
  QFile F ( filename )                                   ;
  if ( ! F . open ( QIODevice::WriteOnly                 |
                    QIODevice::Truncate ) ) return false ;
  F . write ( data )                                     ;
  F . close (      )                                     ;
  return true                                            ;
}

///////////////////////////////////////////////////////////////////////////////

QT_END_NAMESPACE
