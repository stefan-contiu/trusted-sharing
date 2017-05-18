import sys
import cmd

from user_api import User
from group_api import AdminGroupManagement
from crypto import UserKeyLoader, PubKeysLookup
from util import ccolor
from timeit import default_timer as timer

class CmdClient(cmd.Cmd):

    def init(self, user):
        user_count = PubKeysLookup.load()
        print('Loaded Trusted Directory of %d Public Keys.' % user_count)

        self.prompt = ccolor.wrap(user) + '> '
        pri_key = UserKeyLoader.pri_key(user)
        pub_key = UserKeyLoader.pub_key(user)
        print('Pri & Pub keys loaded for user ', ccolor.wrap(user))
        self.u = User(user, pri_key, pub_key)
        self.user_name = user

    def do_list(self, line):
        print('List files of user : ' + ccolor.wrap(self.user_name))
        start = timer()

        files = self.u.list_files()
        if files:
            for f_name in list(files.keys()):
                print ('  [not shared]  ' + ccolor.wrap(f_name) + '\t' +
                    str(int(files[f_name]['size']/1024))  + " KB")
                # TODO: for each referenced group, retreived files
        else:
            print('  (empty)  ')

        end = timer()
        print('Command execution time : %.2f sec' % (end - start))

    def do_clear(self, line):
        print('Deleting all content of user : ' + ccolor.wrap(self.user_name))
        start = timer()
        self.u.clear_all()
        end = timer()
        print('Command execution time : %.2f sec' % (end - start))

    def do_upload(self, line):
        files = line.split()
        print('Uploading %s files for user : %s '
            % (ccolor.wrap(str(len(files))), ccolor.wrap(self.user_name)))
        start = timer()
        self.u.upload_files(files)
        end = timer()
        print('Command execution time : %.2f sec' % (end - start))

    def do_download(self, line):
        files = line.split()
        print('Downloading %s files for user : %s '
            % (ccolor.wrap(str(len(files))), ccolor.wrap(self._user_id)))
        start = timer()
        self.u.download_files(files)
        end = timer()
        print('Command execution time : %.2f sec' % (end - start))


    ######################################################################
    def do_group(self, line):
        args = line.split()
        if (args[0] == 'create'):
            self.create_group(args[1:])
        elif (args[0] == 'add'):
            self.add_group_member()
        else:
            print('Unknown group command')

    def create_group(self, args):
        group_name = args[0]
        group_members = args[1:]
        print('Creating a new group ' + ccolor.group(group_name)
            + ' with members : ', group_members)
        start = timer()
        g = AdminGroupManagement(self.user_name)
        g.create_group(group_name, group_members)
        g.push_changes()
        end = timer()
        print('Command execution time : %.2f sec' % (end - start))

    def add_group_member(self, args):
        group_name = args[0]
        group_members = args[1:]
        print('Add to group ' + ccolor.group(group_name)
            + ' members : ', group_members)
        start = timer()
        g = AdminGroupManagement(self.user_name)
        g.add_members(group_name, group_members)
        g.push_changes()
        end = timer()
        print('Command execution time : %.2f sec' % (end - start))

    def do_exit(self, line):
        return True


if __name__ == "__main__":
    user_name = sys.argv[1]
    c = CmdClient()
    c.init(user_name)
    c.cmdloop()
