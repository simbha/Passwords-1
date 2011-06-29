#!/usr/bin/python

#
# LICENSE:
#  Copyright 2011, jtmaher
#
#  This program is free software: you can redistribute it and/or modify	
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import hashlib
import os
import json 
import sys
import getpass
import base64
from optparse import OptionParser


# The location of the password database
PASSWORD_DATABASE = os.path.expanduser( '~/.passwords' )

# The alphabet used for the generated passwords
ALPHABETS = { 
    'all': '''ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890-=`~!@#$%^&*()_+{}|[]:;?/'"''',
    'nosymb': '''ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv1234567890''' }

# Additional salt used for verification hashes
NUMS = 'NOTHING UP MY SLEEVES'


class UsageError( Exception ):
    def __init__( self, msg ):
        self.msg = msg

def get_options():
    opt = OptionParser()
    opt.add_option( '-d', '--difficulty',
                    dest='difficulty',
                    default=0xFFFF,
                    type='int',
                    help='Number of iterations of hash function' )
    opt.add_option( '-l', '--length',
                    dest='length',
                    default=32,
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
    
    (opts,args) = opt.parse_args()
    opt.usage += ' [create|get|list|delete]'
    return (opt,opts,args)

# If possible, output password to clipboard
try:
    import pygtk
    pygtk.require('2.0')
    import gtk
    use_clipboard = True

except ImportError:
    use_clipboard = False

def copy_to_clipboard( passwd ):
    clipboard = gtk.clipboard_get()
    clipboard.set_text( passwd )
    clipboard.store()
    print "Password copied to clipboard."

def compute_password( passwd, n_iter ):
    for i in range(n_iter):
        m = hashlib.sha512()
        m.update(passwd)
        passwd = m.digest()
    return passwd

def alpha_encode(msg,length,alphabet):
    try:
        chars = ALPHABETS[alphabet]
    except KeyError:
        print "Error: Unknown alphabet %s" % alphabet
        sys.exit(1)

    n = 0
    for i in range( len(msg) ):
        n += ord(msg[i]) * (256**i)
    arr = []
    base = len(chars)
    while n:
        rem = n % base
        n = n // base
        arr.append(chars[rem])
    arr.reverse()
    return ''.join(arr[0:length])


    
def load_database():
    try:
        f  = open( PASSWORD_DATABASE, 'r' )
        db = json.loads( f.read() )
        f.close()

    except IOError:
        db = {}

    return db


def save_database(db):
    try:
        f = open( PASSWORD_DATABASE, 'w' )
        f.write( json.dumps(db, sort_keys=True, indent=2 ) )
        f.close()
    except IOError:
        print "Error: Cannot write database file: %s" % PASSWORD_DATABASE
        sys.exit(1)


def create_pw(db,opts):
    if opts.user_host == None:
        raise UsageError( 'Need a user/hostname option for password creation.')
    print "Creating password for %s (%s)..." % (opts.user_host, opts.memo)

    passwd  = getpass.getpass( "Password: " )
    passwd2 = getpass.getpass( "Re-enter: " )

    if not passwd == passwd2:
        print "Passwords do not match. Please try again."
        sys.exit
    
    print "Computing password..."
    
    passwd += opts.user_host
    
    mypass = compute_password( 
        passwd, 
        opts.difficulty )

    mypass_check = compute_password(
        passwd + NUMS, 
        opts.difficulty )

    if not use_clipboard or opts.verbose:
        print alpha_encode( mypass, opts.length, opts.alphabet )
    else:
        copy_to_clipboard( 
            alpha_encode( mypass, opts.length, opts.alphabet ) )

    db[opts.user_host] = { 
        'length':     opts.length,
        'difficulty': opts.difficulty,
        'alphabet':   opts.alphabet,
        'check_hash': base64.b64encode( mypass_check ),
        'memo':       opts.memo }
    
    
    
def get_pw(db,opts):
    if not db.has_key( opts.user_host ):
        print "I don't have a password for %s" % opts.user_host
    record = db[opts.user_host]

    passwd  = getpass.getpass( "Password: " )
    passwd += opts.user_host

    try:
        passwd_check = compute_password( passwd + NUMS, record['difficulty'] )
        
        if not base64.b64encode(passwd_check) == record['check_hash']:
            print "Incorrect password. Please try again."
            sys.exit(1)
            
        print "Computing password..."

        result = compute_password( passwd, record['difficulty'] )
    
        if not use_clipboard or opts.verbose:
            print alpha_encode(
                result, record['length'], record['alphabet'] )
        else:
            copy_to_clipboard(
                alpha_encode(result, record['length'], record['alphabet']) )

    except KeyError as err:
        print "KeyError: Database entry has no key %s" % err
        sys.exit(1)
        
def list_pw(db,opts):
    for user_host in db:
        record = db[user_host]
        print '%s (%s)' % (user_host, record['memo'])
    

def delete_pw(db,opts):
    if db.has_key( opts.user_host ):
        question = "Are you sure you want to delete %s (%s) from the database? [y/N]"
        resp = raw_input( question % ( opts.user_host, opts.memo ))
        if resp == 'y':
            del db[ opts.user_host ]
        else:
            print "Nothing done."
            
    else:
        print "No password for %s found in database." % opts.user_host
        sys.exit(1)

if __name__ == "__main__":
    db = load_database()        
    
    (parser,opts,args) = get_options()
    
    actions = { 'create': create_pw,
                'get':    get_pw,
                'list':   list_pw,
                'delete': delete_pw }
    
    try:
        if len(args) != 1 or not actions.has_key(args[0]):
            raise UsageError( "Need an action: create, get, list or delete.")
        else:
            action = args[0]

            actions[action](db,opts)
            
    except UsageError as u:
        print u.msg
        parser.print_help()
        sys.exit(1)
        
    except KeyboardInterrupt:
        print
        sys.exit(1)
        
    save_database( db )
        
