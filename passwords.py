#!/usr/bin/python

"""
LICENSE:

Copyright 2011, jtmaher

This program is free software: you can redistribute it and/or modify	
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import hashlib
import os
import json 
import sys
import getpass
import base64
from optparse import OptionParser


# The location of the password database...
# Edit this to specify an alternate location
PASSWORD_DATABASE = os.path.expanduser( '~/.passwords' )
DEFAULT_LENGTH = 32
DEFAULT_DIFFICULTY = 0xFFFF

# The alphabet used for the generated passwords
ALPHABETS = { 
    'all': """ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmno""" + 
    """pqrstuvwxyz1234567890-=`~!@#$%^&*()_+{}|[]:;?/"'""",
    'nosymb': """ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv1234567890""" 
    # You can add additional alphabets here if necessary
    }

# Additional salt used for verification hashes
NUMS = 'NOTHING UP MY SLEEVES'

# Used to identify password database
MAGIC_VALUE = 'PASSWORDS12345'
MAGIC_KEY   = 'MAGIC_KEY'


class UsageError( Exception ):
    """Catch-all error message"""

    def __init__( self, msg ):
        self.msg = msg
        Exception.__init__(self)


def get_options():
    """Configures the options"""

    opt = OptionParser()

    opt.add_option( '-d', '--difficulty',
                    dest='difficulty',
                    default=DEFAULT_DIFFICULTY,
                    type='int',
                    help='Number of iterations of hash function' )

    opt.add_option( '-l', '--length',
                    dest='length',
                    default=DEFAULT_LENGTH,
                    type='int',
                    help='Password length' )

    opt.add_option( '-u', '--user_host', 
                    dest='user_host',
                    default=None,
                    help='username@host or other name for the password' )

    opt.add_option( '-a', '--alphabet',
                    dest='alphabet',
                    default='all',
                    help='Alphabet to use for password' )

    opt.add_option( '-m', '--memo', 
                    dest='memo',
                    default='',
                    help='Notes' )

    opt.add_option( '-v', '--verbose',
                    dest='verbose',
                    default=False,
                    action='store_true',
                    help='Verbose mode' )
    
    (myopts, myargs) = opt.parse_args()
    opt.usage += ' [create|get|list|delete]'
    return (opt, myopts, myargs)


# If possible, output password to clipboard
# This currently requires GTK
USE_CLIPBOARD = False
if os.environ.has_key( 'DISPLAY' ):
    try:
        import pygtk
        pygtk.require('2.0')
        import gtk
        USE_CLIPBOARD = True
        
    except ImportError:
        pass


def copy_to_clipboard( passwd ):
    """Write the password to the GTK clipboard"""

    clipboard = gtk.clipboard_get()
    clipboard.set_text( passwd )
    clipboard.store()
    print "Password copied to clipboard."


def compute_password( passwd, n_iter ):
    """Compute the iterated sha512sum"""

    while n_iter > 0:
        myhash = hashlib.sha512()
        myhash.update(passwd)
        passwd = myhash.digest()
        n_iter -= 1
    return passwd


def alpha_encode(msg, length, alphabet):
    """Encode the password in the chosen alphabet"""

    try:
        chars = ALPHABETS[alphabet]
    except KeyError:
        print "Error: Unknown alphabet %s" % alphabet
        sys.exit(1)

    num = 0
    for i in range( len(msg) ):
        num += ord(msg[i]) * (256**i)
    arr = []
    base = len(chars)
    while num:
        rem = num % base
        num = num // base
        arr.append(chars[rem])
    arr.reverse()
    return ''.join(arr[0:length])


def output_password( passwd, opts ):
    """
    Display password to the user or copy to 
    clipboard if possible.
    """

    result = alpha_encode( passwd, opts.length, opts.alphabet )

    if not USE_CLIPBOARD or opts.verbose:
        print result
    else:
        copy_to_clipboard( result )


def load_database():
    """Load JSON password database"""

    try:
        myfile = open( PASSWORD_DATABASE, 'r' )
        mydb = json.loads( myfile.read() )

        if( not mydb.has_key(MAGIC_KEY) or 
            not mydb[MAGIC_KEY] == MAGIC_VALUE ):
            raise ValueError()

        del mydb[MAGIC_KEY]

        myfile.close()

    except IOError:
        mydb = {}

    except ValueError:
        print( "The file \"%s\" is not a passwords.py database."
               % PASSWORD_DATABASE )
        print(
            "Please configure a different "
            + "path for PASSWORD_DATABASE." )
        sys.exit(1)

    return mydb


def save_database(mydb):
    """Save JSON password database"""

    # Set magic key to identify file
    mydb[MAGIC_KEY] = MAGIC_VALUE

    try:
        myfile = open( PASSWORD_DATABASE, 'w' )
        myfile.write( json.dumps(mydb, sort_keys=True, indent=2 ) )
        myfile.close()
    except IOError:
        print "Error: Cannot write database file: %s" % PASSWORD_DATABASE
        sys.exit(1)


def create_pw(mydb, opts):
    """Create a new password"""
    
    if opts.user_host == None:
        raise UsageError( 'Need a user/hostname option for password creation.')

    if mydb.has_key(opts.user_host):
        msg  = 'Error: I already have a password for %s.\n' % opts.user_host
        msg += 'Please delete it from the database if you want to replace it:\n'
        msg += '  ./passwords.py delete -u %s' % opts.user_host
        raise UsageError( msg )

    print "Creating password for %s (%s)..." % (opts.user_host, opts.memo)

    passwd  = getpass.getpass( "Password: " )
    passwd2 = getpass.getpass( "Re-enter: " )

    if not passwd == passwd2:
        print "Passwords do not match. Please try again."
        sys.exit(1)
    
    print "Computing password..."
    
    passwd += opts.user_host
    
    mypass = compute_password( 
        passwd, 
        opts.difficulty )

    ## This is the verification password for the database
    mypass_check = compute_password(
        passwd + NUMS, 
        opts.difficulty )

    output_password( mypass, opts )
    
    mydb[opts.user_host] = { 
        'length':     opts.length,
        'difficulty': opts.difficulty,
        'alphabet':   opts.alphabet,
        'check_hash': base64.b64encode( mypass_check ),
        'memo':       opts.memo }
        
    
def get_pw( mydb, opts):
    """Retrieve a password from database"""

    if not mydb.has_key( opts.user_host ):
        print "I don't have a password for %s" % opts.user_host
        sys.exit(1)

    record = mydb[opts.user_host]

    passwd  = getpass.getpass( "Password: " )
    passwd += opts.user_host

    try:
        passwd_check = compute_password( passwd + NUMS, record['difficulty'] )
        
        if not base64.b64encode(passwd_check) == record['check_hash']:
            print "Incorrect password. Please try again."
            sys.exit(1)
            
        print "Computing password..."

        result = compute_password( passwd, record['difficulty'] )
    
        opts.length = record['length']
        opts.alphabet = record['alphabet']

        output_password( result, opts )

    except KeyError as err:
        print "KeyError: Database entry has no key %s" % err
        sys.exit(1)
        

def list_pw( mydb, opts ):
    """List passwords in the databas"""

    for user_host in mydb:
        record = mydb[user_host]
        if opts.verbose:
            print '%s (%s)' % (user_host, record['memo'])
        else:
            print user_host


def delete_pw( mydb, opts ):
    """Delete a password from the database"""

    if mydb.has_key( opts.user_host ):
        question = "Are you sure you want to delete %s"
        question += " (%s) from the database? [y/N]"
        resp = raw_input( question % ( opts.user_host, opts.memo ))
        if resp == 'y':
            del mydb[ opts.user_host ]
        else:
            print "Nothing done."
            
    else:
        print "No password for %s found in database." % opts.user_host
        sys.exit(1)


def main():
    """The main function"""

    mydb = load_database()        
    
    (parser, opts, args) = get_options()
    
    actions = { 'create': create_pw,
                'get':    get_pw,
                'list':   list_pw,
                'delete': delete_pw }
    
    try:
        if len(args) != 1 or not actions.has_key(args[0]):
            raise UsageError( "Need an action: create, get, list or delete.")
        else:
            action = args[0]
            actions[action](mydb, opts)
            
    except UsageError as uerr:
        print uerr.msg
        if opts.verbose:
            parser.print_help()
        sys.exit(1)
        
    except KeyboardInterrupt:
        print
        sys.exit(1)
        
    save_database( mydb )


if __name__ == "__main__":
    main()
