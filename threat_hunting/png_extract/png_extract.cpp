#include "stdafx.h"
#include <windows.h>

#include <gdiplus.h>
#pragma comment(lib, "gdiplus.lib")

#include <gdiplusinit.h>
#include <gdiplusmem.h>

using namespace Gdiplus;

///////////////////////////////////

int 
main( int argc, char* argv[] )
{
    DWORD offset             = 0;
    ULONG_PTR gdi            = NULL;
    GdiplusStartupInput gi   = { 0 };
    GdiplusStartupOutput* go = NULL;

    if ( argc != 3 )
    {
        printf( "usage: %s <input.exe> <output file name>\n", argv[ 0 ] );
        return 1;
    }

    Status ret = GdiplusStartup( &gdi, &gi, NULL );

    if ( ret != Status::Ok )
    {
        printf( "Unable to initialize GdiplusStartup: %d\n", ret );
        return 1;
    }

    if ( !gdi )
    {
        printf( "Invalid GdiplusStartup token\n" );
        return 1;
    }

    /* extract from PE passed on command line */

    HMODULE peh = LoadLibraryA( argv[ 1 ] );

    if ( !peh )
    {
        printf( "Unable to load %s: %d\n", argv[ 1 ], GetLastError() );
        return 1;
    }

    HANDLE hf = CreateFileA( argv[ 2 ], GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL );

    if ( hf == INVALID_HANDLE_VALUE ) 
    {
        printf( "Unable to create output file %s: %d\n", argv[ 2 ], GetLastError() );
        return 1;
    }

    /* loop over all png files */

    bool done = false;
    int index = 1;

    while ( !done )
    {
        HRSRC png = FindResourceA( peh, LPCSTR( MAKEINTRESOURCE( index ) ), "PNG" );

        if ( !png )     /* no more left */
            break;

        DWORD sz     = SizeofResource( peh, png );
        HGLOBAL hpng = LoadResource( peh, png );

        if ( !hpng )
        {
            printf( "Could not load resource at index %d: %d\n", index, GetLastError() );
            break;
        }

        void* raw  = ( BYTE* )LockResource( hpng );
        HANDLE buf = GlobalAlloc( GMEM_MOVEABLE, sz );

        if ( !buf )
        {
            printf( "Could not allocate via GlobalAlloc: %d\n", GetLastError() );
            break;
        }

        void* pbuf = GlobalLock( buf );

        CopyMemory( pbuf, raw, sz );

        IStream* stream = NULL;

        if ( CreateStreamOnHGlobal( buf, FALSE, &stream ) != S_OK )
        {
            printf( "Could not create stream: %d\n", GetLastError() );
            break;
        }

        Bitmap bm( stream, false );
        stream->Release();

        /* NOTE: PixelFormat16bppARGB1555 == 0x61007 as seen in malware */

        BitmapData* bdata = new BitmapData;

        /* NOTE: malware specified 0x7 which == ImageLockModeRead | ImageLockModeWrite | ImageLockModeUserInputBuf, but this blows up, ImageLockModeRead works fine */

        Status lock_status = bm.LockBits( NULL, ImageLockModeRead, PixelFormat16bppARGB1555, bdata );

        if ( lock_status != Ok )
            break;

        /* Display the hexadecimal value of each pixel */

        UINT* pixels = ( UINT* )bdata->Scan0;

        DWORD written = 0;
        BOOL err      = WriteFile( hf, pixels, bdata->Height * bdata->Width * 2, &written, NULL );      /* x2 is for 16bpp */

        index++;
    }

    CloseHandle( hf );

    GdiplusShutdown( gdi );

    return 0;
}
