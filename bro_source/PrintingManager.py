

class PrintingManager(object):

    def __init__(self):
        super(PrintingManager, self).__init__()
        self.verbosity = 1

    def init_hello(self, verbosity):
        self.verbosity = verbosity
        self.space_1 = '    '
        self.space_2 = self.space_1 + self.space_1

        # my approach
        # print('        _____  _____   ___    ___        ___     ___  _____   ___    ')
        # print('|    |    |      |    |   \  /   \      |   \   |       |    |       ')
        # print('|____|    |      |    |___/  \___       |    \  |___    |    |___    ')
        # print('|    |    |      |    |          \      |    /  |       |    |       ')
        # print('|    |    |      |    |      \___/      |___/   |___    |    |___        ')
        # Generated approach

        print(' _    _ _______ _______ _____   _____     _____  ______ _______ ______ _____ _______ ____  _____     ')
        print('| |  | |__   __|__   __|  __ \ / ____|   |  __ \|  ____|__   __|  ____/ ____|__   __/ __ \|  __ \    ')
        print('| |__| |  | |     | |  | |__) | (___     | |  | | |__     | |  | |__ | |       | | | |  | | |__) |   ')
        print('|  __  |  | |     | |  |  ___/ \___ \    | |  | |  __|    | |  |  __|| |       | | | |  | |  _  /    ')
        print('| |  | |  | |     | |  | |     ____) |   | |__| | |____   | |  | |___| |____   | | | |__| | | \ \    ')
        print('|_|  |_|  |_|     |_|  |_|    |_____/    |_____/|______|  |_|  |______\_____|  |_|  \____/|_|  \_\   ')

        print('\nHTTPS Detector tool. Author: Frantisek Strasak, strasfra@fel.cvut.cz, '
              'verbosity: {}\n'.format(self.verbosity))

    def print_data_statistic(self):
        if self.verbosity > 0:
            print("Loaded bro files:")
            print(self.space_1 + 'conn.log files: {}'.format(len(self.conn_files)))
            if self.verbosity > 1:
                for cfile in self.conn_files:
                    print(self.space_2 + cfile)
            print(self.space_1 + 'ssl.log files: {}'.format(len(self.ssl_files)))
            if self.verbosity > 1:
                for sfile in self.ssl_files:
                    print(self.space_2 + sfile)
            print(self.space_1 + 'x509.log files: {}'.format(len(self.x509_files)))
            if self.verbosity > 1:
                for xfile in self.x509_files:
                    print(self.space_2 + xfile)


    def print_detection_result(self):
        print('len of tuple keys {}'.format(len(self.connection_4_tuples.keys())))
        # for key in self.connection_4_tuples.keys():
        #     print(key)
