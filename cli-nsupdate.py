#!/usr/bin/python

import dns.resolver, ipaddress
from subprocess import Popen, PIPE

SUBNETS = {}
RESOLVER = dns.resolver.Resolver()
RESOLVER.nameservers = ['127.0.0.1']

def get_hostname(mode=None, display='Hostname: '):
        '''
        Get hostname from user
        @param mode add, remove, mx, or None
        @return hostname from user
        '''

        hostname = ''
        while hostname == '':
                hostname = raw_input(display)
                if hostname == '':
                        continue
                checkForQuit(hostname)
                hostname = parse_hostname(hostname)
                avail = hostname_avail(hostname)

                # If adding an A/CNAME record, make sure hostname doesn't already exist
                if not avail and mode == 'a':
                        print '%s already has a record' % hostname
                        hostname = ''

                # If removing an A/CNAME  record, make sure hostname actually exists
                elif avail and mode == 'r':
                        print '%s does not have a record to remove' % hostname
                        hostname = ''

                # If adding a MX/CNAME record, make sure the hostname already has an A record
                elif avail and mode in ('mx', 'cname'):
                        print '%s does not have a record' % hostname
                        hostname = ''

        return hostname

def parse_hostname(hostname):
        '''
        Parse hostname
        @param user supplied hostname
        @return sanitized hostname
        '''

        # Remove dot at end if supplied, will add it back on later
        if hostname[-1] == '.':
                hostname = hostname[:-1]

        # Default to local.localdomain
        if len(hostname) < 12 or hostname[-12:] not in ('local.localdomain', 'examlpe.com'):
                hostname += 'local.localdomain'
        return hostname + '.'

def hostname_avail(hostname):
        '''
        Check if hostname is avaliable
        @param hostname to check
        @return True if hostname is unused
        '''

        try:
                # this seems to check all hostnames, not just A
                RESOLVER.query(hostname, 'A')
                return False
        except:
                return True

def get_ip():
        '''
        Get IP from user
        @return IP from user
        '''

        ip = ''
        while ip == '':
                ip = raw_input('IP: ')
                if ip == '':
                        continue
                checkForQuit(ip)
                if not valid_ip(ip):
                        print 'Invalid IP'
                        ip = ''
                if not ip_avail(ip):
                        print 'IP is currently in use'
                        check = ''
                        while check == '':
                                check = raw_input('Are you sure you want to add another record to this IP (y/[n]) ').lower() or 'n'
                                checkForQuit(check)
                                if check not in ('y', 'yes', 'n', 'no'):
                                        check = ''
                                else:
                                        if check in ('n', 'no'):
                                                ip = ''
        return ip


def valid_ip(ip):
        '''
        Checks to make sure IP is valid
        @param ip the to check
        @return True if IP is valid IPv4 IP
        '''

        octets = ip.split('.')
        if len(octets) != 4:
                return False
        for octet in octets:
                if not octet.isdigit():
                        return False
                oct = int(octet)
                if oct < 0 or oct > 255:
                        return False
        return True

def ip_avail(ip):
        '''
        Check if IP is available
        @param IP to check
        @return True if ip is available
        '''

        try:
                RESOLVER.query(ipaddress.ip_address(u'%s' % ip).reverse_pointer, 'PTR')
                return False
        except:
                return True

def rdns(ip):
        '''
        Do a reverse DNS lookup by using dig
        gethostbyaddr will only return one hostname, rather than all
        @param ip the IP to lookup
        @return an array of hostnames
        '''

        pipe = Popen(['dig', '-x', ip, '+short', '@127.0.0.1'], stdout=PIPE)
        out, err = pipe.communicate()
        if len(out) > 0:
                return out.rstrip().split('\n')
        return []

def get_priority():
        '''
        Get MX priority from user
        @return an integer [0, 65535]
        '''

        priority = ''
        while priority == '':
                priority = raw_input('Enter a priority: ')
                if priority == '':
                        continue
                checkForQuit()
                if not priority.isdigit():
                        print 'Please enter an integer [0, 65535]'
                        priority = ''
                        continue
                p = int(priority)
                if p < 0:
                        print 'Please enter a positive integer'
                        priority = ''
                elif p > 65535:
                        print 'Please enter an interger less than 65536'
                        priority = ''
        return priority

def follow_cname(host, all_records):
        '''
        Follow CNAME chain
        @param host beginning of CNAME chain
        @param all_records a list of all records
        @return list of CNAME records
        '''

        for record in all_records:
                r = record.split()
                if len(r) > 3 and host == r[-1] and 'CNAME' == r[3]:
                        return [record] + follow_cname(r[0], all_records)

        return []

def get_mx(host, all_records):
        '''
        Check for any MX records
        @param host the host to check for MX records
        @param all_records a list of all records
        @return a list of MX records
        '''

        mx = []
        for record in all_records:
                r = record.split()
                if len(r) > 3 and host == r[-1] and 'MX' == r[3]:
                        mx.append(record)
        return mx

def send_query(q):
        '''
        Send query using nsupdate
        @param q query to send
        '''

        # all queries need to specify localhost at the beginning
        # and then send the query at the end
        # followed by safely quitting nsupdate
        query = 'server localhost\n' + q + 'send\nquit\n'


        # send query, specifying key file
        pipe = Popen(['nsupdate', '-k', '/etc/bind/rndc.key'], stdin=PIPE)
        pipe.communicate(input=query)

def full_record():
        '''
        Get a complete copy of DNS
        @return output of dig -t AXFR
        '''

        ns_pipe = Popen(['dig', '-t', 'AXFR', 'local.localdomain', '@127.0.0.1'], stdout=PIPE)
        ns_result, err = ns_pipe.communicate()

        return [ns_result]

def backup_dns():
        '''
        Backup a complete copy of DNS
        '''

        all_records = full_record()
        out_filepath = '/tmp/db'

        # local.localdomain
        f = open('%s/db.local' % out_filepath, 'w')
        f.write(all_records[0])
        f.close()


        # TODO: add to git and fix dir

def get_subnets():
        '''
        Read in subnets.dict
        '''

        global SUBNETS

        f = open('/var/cache/bind/subnets.dict', 'r')
        subs = f.readlines()
        f.close()
        for sub in subs:
                s = sub.strip('\n').split('/')
                SUBNETS[s[0]] = s[1]

def menu():
        '''
        Print and process main menu
        @return mode
        '''
        options = ['Add Record (Default)', 'Remove Record', 'View Subnet', 'Quit']
        print '+======================+'
        print '|         Menu         |'
        print '+======================+'
        for i in range(len(options)):
                print '%d) %s' % (i + 1, options[i])
        print
        mode = ''
        while mode == '':
                mode = raw_input('Enter choice: ').lower() or '1'
                if mode == '4':
                        mode = 'q'
                checkForQuit(mode)
                if mode not in ('1', '2', '3', '4'):
                        mode = ''
        return mode

def print_subnet():
        '''
        Print all IPs in subnet
        '''

        subnet = ''
        while subnet == '':
                subnet = raw_input('Enter subnet: ')
                if subnet == '':
                        continue
                checkForQuit(subnet)

                # ignore subnet mask if entered
                if '/' in subnet:
                        subnet = subnet.split('/')[0]

                # if less than four octets, add zeroes
                octets = subnet.split('.')
                if len(octets) < 4:
                        for i in range(4 - len(octets)):
                                octets.append('0')

                # make sure it isn't a /32
                if octets[-1] != '0':
                        print 'Not a valid subnet'
                        subnet = ''
                        continue

                subnet = '.'.join(octets)

                # make sure subnet is valid
                if not valid_ip(subnet):
                        print 'Not a valid subnet'
                        subnet = ''
                        continue


                # make sure subnet is one of ours
                if subnet not in SUBNETS:
                        found = False
                        sub = ipaddress.IPv4Network(u'%s/24' % subnet)
                        for s in SUBNETS:
                                if sub.subnet_of(ipaddress.IPv4Network(u'%s/%s' % (s, SUBNETS[s]))):
                                        found = True
                                        ip_range = sub
                                        break

                        if not found:
                                print 'Not a subnet in subnets.dict'
                                subnet = ''
                else:
                        ip_range = ipaddress.IPv4Network(u'%s/%s' % (subnet, SUBNETS[subnet]))
        full = full_record()
        all_records = (full[0] + full[1]).split('\n')

        i = 0

        for ip in ip_range.hosts():
                ip = str(ip)
                if ip[-2:] == '.0' or ip[-4:] == '.255':
                        continue
                found = False
                for record in all_records:
                        if record.endswith(ip):
                                print record

                                # Follow CNAMEs
                                for cname in follow_cname(record.split()[0], all_records):
                                        print cname

                                #Check for MX records
                                for mx in get_mx(record.split()[0], all_records):
                                        print mx
                                found = True
                if not found:
                        print ';free\t%s' % ip

                # pause for scrolling, good for networks bigger than /24
                i += 1
                if i == 255:
                        pause = raw_input('Press the <ENTER> key to continue...') or None
                        if pause != None and pause.lower() in ('quit', 'q', 'exit'):
                                break
                        i = 0

def checkForQuit(input):
        '''
        Checks user prompt for quit
        @input user's input
        '''
        if input.lower() in ('quit', 'q', 'exit'):
                exit(0)

def main():
        get_subnets()
        while 1:
                mode = menu()
                record = ''

                # Print subnet
                if mode == '3':
                        print_subnet()
                        continue

                # Read in record type, defaulting to A
                while record == '':
                        record = raw_input('Record type ([A]/CNAME/MX): ').upper() or 'A'
                        checkForQuit(record)

                        # Verify valid record type
                        if record not in ('A', 'CNAME', 'MX'):
                                record = ''

                # Add A record and PTR
                if record == 'A' and mode == '1':
                        hostname = get_hostname(mode='a')
                        ip = get_ip()
                        send_query('update add %s 300 IN A %s\n' % (hostname, ip))
                        rev_ip = ipaddress.ip_address(u'%s' % ip).reverse_pointer
                        send_query('update add %s. 300 IN PTR %s\n' % (rev_ip, hostname))

                # Remove A record and PTR
                elif record == 'A' and mode == '2':
                        hostname = get_hostname(mode='r')
                        ip = str(RESOLVER.query(hostname, 'A')[0])
                        send_query('update delete %s\n' % hostname)
                        rev_ip = ipaddress.ip_address(u'%s' % ip).reverse_pointer
                        send_query('update delete %s. IN PTR %s\n' % (rev_ip, hostname))

                # Add CNAME
                elif record == 'CNAME' and mode == '1':
                        cname = get_hostname(mode='a', display='CNAME: ')
                        hostname = get_hostname(mode='cname')
                        send_query('update add %s 300 IN CNAME %s\n' % (cname, hostname))

                # Remove CNAME
                elif record == 'CNAME' and mode == '2':
                        cname = get_hostname(mode='r', display='CNAME: ')
                        send_query('update delete %s CNAME\n' % cname)

                # Add MX record
                elif record == 'MX' and mode == '1':
                        domain = get_hostname(display='Domain: ')
                        hostname = get_hostname(mode='mx')
                        priority = get_priority()
                        send_query('update add %s 300 IN MX %s %s\n' % (domain, priority, hostname))

                # Remove MX record
                elif record == 'MX' and mode == '2':
                        domain = get_hostname(display='Domain: ')
                        hostname = get_hostname()
                        priority = get_priority()
                        send_query('update delete %s 300 IN MX %s %s\n' % (domain, priority, hostname))

                # Shouldn't make it this far
                else:
                        print 'Invalid record type (shouldn\'t see this error)'
                        exit(1)

                #backup_dns()

if __name__ == '__main__':
        main()

