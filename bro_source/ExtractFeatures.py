import os
from .ConnectionFeatures import ConnectionFeatures
from .CertificateFeatures import CertificateFeatures
# from .PrintingManager import PrintingManager

class ExtractFeatures(object):

    def __init__(self):
        self.connection_4_tuples = dict()

        self.x509_dict = dict()
        self.control_ssl_uids_dict = dict()

        self.tuples_keys = None

        self.number_conn_lines = 0
        self.conn_dict = dict()

        self.err_conn_uids = 0
        self.err_more_same_X509 = 0
        self.err_not_added_x509 = 0

        self.ssl_lines = 0
        self.not_founded_x509_lines = 0
        self.founded_x509_lines = 0

        self.certificate_dict = dict()

        self.dataset_inforamtion_dict = dict()

        self.normal_src_IP_dict = dict()
        self.malware_src_IP_dict = dict()

        self.reading_time_file = []

        self.root_certs = load_root_cert()
        self.alexa_1000_arr = load_alexa_1000()
        self.malware_alexa_ssl_aggregation = 0
        self.normal_alexa_ssl_aggregation = 0
        self.malware_ssl_aggregation = 0
        self.normal_ssl_aggregation = 0

        # Check unique ssl connection
        self.normal_same_connections_dict = dict()
        self.malware_same_connections_dict = dict()
        self.unique_malware_alexa_ssl_aggregation = 0
        self.unique_normal_alexa_ssl_aggregation = 0

        # For printingManager
        self.conn_files = []
        self.ssl_files = []
        self.x509_files = []

    def extraction_manager(self, dataset_path_to_logs):
        # Loads all conn logs in bro folder.
        self.conn_files = self.conn_logs(dataset_path_to_logs)
        # Loads all x509 logs in bro folder.
        self.x509_files =  self.x509_logs(dataset_path_to_logs)
        # Load all ssl logs.
        self.ssl_files = self.ssl_logs(dataset_path_to_logs)
        # Find not ssl lines in conn.logs that belong to created conn 4 tuples.
        self.conn_logs_2(dataset_path_to_logs)

        self.ssl_lines = 0
        self.not_founded_x509_lines = 0
        self.founded_x509_lines = 0
        self.err_not_added_x509 = 0

    """
    ---------------------- Conn logs. -------------------------
    """
    def conn_logs(self, dataset_path_to_logs):
        # print(" << Read all conn logs:")
        # print("Reading conn logs:")
        self.number_conn_lines = 0
        # all_conn_logs = get_such_logs(dataset_path_to_logs, ['conn', '_label'])
        all_conn_logs = get_such_logs(dataset_path_to_logs, ['conn'])
        for conn_log in all_conn_logs:
            self.read_conn_log(dataset_path_to_logs + conn_log)
        # print("     << Loaded conn logs: ", len(all_conn_logs))
        return all_conn_logs

    def read_conn_log(self, dataset_path_to_conn):
        try:
            with open(dataset_path_to_conn) as f:
                for line in f:
                    if line[0] == '#':
                        continue
                    split_conn_line = line.split('	')
                    conn_uid = split_conn_line[1]

                    # label = split_conn_line[21]

                    # if 'Background' in label or 'No_Label' in label:
                    #     continue

                    try:
                        if self.conn_dict[conn_uid]:
                            # print("Error: more same conn line !")
                            pass
                    except:
                        self.conn_dict[conn_uid] = line
            f.close()
        except IOError:
            print("Error: The conn file: " + dataset_path_to_conn + " does not exist.")

    """
    --------------------- X509 logs. ------------------------
    """
    def x509_logs(self, dataset_path_to_logs):
        # print("<< Read all x509 logs:")
        # Clear x509_dict()
        self.x509_dict = dict()
        all_x509_logs = get_such_logs(dataset_path_to_logs, ['x509'])
        # print("num x509 logs:", len(all_x509_logs))
        for x509_log in all_x509_logs:
            self.read_x509_log(dataset_path_to_logs, x509_log)
        # print("     << Loaded x509 logs: ", len(all_x509_logs))
        return all_x509_logs

    def read_x509_log(self, dataset_path_to_logs, x509_log):
        """
        Read started_file.txt where is time when capture of this dataset starts. Some datasets have starting
        time 1.1. 1970 00:00:00. So we have to add to time.
        If this file does not exist, dataset has right value time.
        """
        # go to parent folder, because 'started_file.txt' is saved in sub folder. Not in bro folder.
        sub_folder = os.path.dirname(dataset_path_to_logs)
        sub_folder = os.path.dirname(sub_folder)
        started_unix_time = 0.0

        try:
            with open(sub_folder + "/start_date.txt") as f:
                started_unix_time = float(f.readlines()[1])
                # print("     << Started unix time file was read in:", sub_folder)
            f.close()
            self.reading_time_file.append(sub_folder)
        except IOError:
            # It means that this dataset has right time format.
            pass

        try:
            with open(dataset_path_to_logs + x509_log) as f:
                # go throw ssl file line by line and for each ssl line check all uid of flows
                for line in f:
                    if '#' == line[0]:
                        continue
                    x509_split = line.split('	')

                    """
                    Change time, because some datasets are from 1.1 1970 00:00:00.
                    """
                    time_new = float(x509_split[0]) + started_unix_time

                    new_line = str(time_new)
                    for i in range(1, len(x509_split)):
                        new_line += '	' + x509_split[i]
                    x509_uid = x509_split[1]
                    try:
                        if self.x509_dict[x509_uid]:
                            self.err_more_same_X509 += 1
                            # print "Error: [read_x509_log] more uids in x509!!!", x509_uid,\
                            #     " and path is: " + dataset_path_to_logs + x509_log
                    except:
                        self.x509_dict[x509_uid] = new_line

            f.close()
        except IOError:
            print("Error: The x509 file: " + dataset_path_to_logs + x509_log + " does not exist.")

    """
    --------------------- SSL logs. ------------------------
    """
    def ssl_logs(self, dataset_path_to_logs):
        # print("<< Read all ssl logs::")
        self.control_ssl_uids_dict = dict()
        all_ssl_logs = get_such_logs(dataset_path_to_logs, ['ssl'])
        for ssl_log in all_ssl_logs:
            self.create_4_tuples(dataset_path_to_logs + ssl_log)
        # print("     << Loaded ssl logs: ", len(all_ssl_logs))
        return all_ssl_logs

    def create_4_tuples(self, path_to_ssl_log):

        with open(path_to_ssl_log) as ssl_file:
            for ssl_line in ssl_file:
                if '#' == ssl_line[0]:
                    continue

                ssl_split = ssl_line.split('	')
                ssl_uid = ssl_split[1]

                # if same ssl, continue (in some ssl.log files are more same ssl lines. It is probably bro error)
                try:
                    if self.control_ssl_uids_dict[ssl_uid]:
                        if ssl_line == self.control_ssl_uids_dict[ssl_uid]:
                            continue
                        else:
                            old_ssl_split = self.control_ssl_uids_dict[ssl_uid].split('	')
                            new_ssl_split = ssl_line.split('	')
                            for i in range(0, len(old_ssl_split)):
                                if i <= 20:
                                    if old_ssl_split[i] != new_ssl_split[i]:
                                        # print("SSL Error - ssl lines with same uid are not same !!!")
                                        # print("     < Path:", path_to_ssl_log)
                                        # print("     < ssl uid:", ssl_uid)
                                        pass
                            continue
                except:
                    self.control_ssl_uids_dict[ssl_uid] = ssl_line

                # find flow in conn.log by this ssl uid.
                try:
                    conn_log = self.conn_dict[ssl_uid]
                except:
                    # conn_dict contains only normal or malware conn lines. Here there are read all ssl lines and
                    # some ssl lines shows to background conn_line that are not contained in conn_dict.
                    continue

                conn_split = conn_log.split('	')
                # 2-srcIpAddress, 4-dstIpAddress, 5-dstPort, 6-Protocol
                connection_index = conn_split[2], conn_split[4], conn_split[5], conn_split[6]

                # try:
                #     label = conn_split[21]
                # except IndexError:
                #     print("Error: no label in conn line.")

                label = "NONE"

                # if 'Background' in label or 'No_Label' in label:
                #     print "Error: Backgroung label."
                #     continue
                #
                # if not ('Botnet' in label) and not ('Normal') in label:
                #     print "Error: Dear more, there are more states of labels !!!!"

                # Save ips to dict
                # if 'Normal' in label:
                #     try:
                #         self.normal_src_IP_dict[conn_split[2]] += 1
                #     except:
                #         self.normal_src_IP_dict[conn_split[2]] = 1
                # if 'Botnet' in label:
                #     try:
                #         self.malware_src_IP_dict[conn_split[2]] += 1
                #     except:
                #         self.malware_src_IP_dict[conn_split[2]] = 1

                try:
                    self.connection_4_tuples[connection_index].add_ssl_flow(conn_log, label)
                except:
                    self.connection_4_tuples[connection_index] = ConnectionFeatures(connection_index)
                    self.connection_4_tuples[connection_index].add_ssl_flow(conn_log, label)

                self.ssl_lines += 1
                # x509 and ssl
                valid_x509_list = self.split_ssl(ssl_line, connection_index, label)

                self.connection_4_tuples[connection_index].add_ssl_log(ssl_line, valid_x509_list,
                                                                       os.path.basename(path_to_ssl_log))

                # For chceking certificate path, find x509 logs in cert path.
                ssl_split = ssl_line.split('	')
                list_of_x509_uids = ssl_split[14].split(',')
                x509_lines_arr = []
                is_founded = True
                for x509_uid in list_of_x509_uids:
                    try:
                        if self.x509_dict[x509_uid]:
                            x509_lines_arr.append(self.x509_dict[x509_uid])
                    except:
                        is_founded = False
                        # break makes an error here.
                self.connection_4_tuples[connection_index].check_certificate_path(x509_lines_arr, is_founded)

                # Find trusted root certificates
                if len(x509_lines_arr) > 0:
                    self.connection_4_tuples[connection_index].check_root_certificate(x509_lines_arr, self.root_certs)

                # Check Alexa 1000
                dst_ip_and_src_ip = conn_split[2], conn_split[4]
                server_name = ssl_split[9]
                if 'Normal' in label:
                    self.normal_ssl_aggregation += 1
                    for alexa_domain in self.alexa_1000_arr:
                        if alexa_domain in server_name or server_name in alexa_domain:
                            self.normal_alexa_ssl_aggregation += 1
                            break
                    # Check for unique
                    try:
                        if self.normal_same_connections_dict[dst_ip_and_src_ip]:
                            self.normal_same_connections_dict[dst_ip_and_src_ip] += 1
                    except:
                        self.normal_same_connections_dict[dst_ip_and_src_ip] = 1
                        for alexa_domain in self.alexa_1000_arr:
                            if alexa_domain in server_name or server_name in alexa_domain:
                                self.unique_normal_alexa_ssl_aggregation += 1
                                break

                if 'Botnet' in label:
                    self.malware_ssl_aggregation += 1
                    for alexa_domain in self.alexa_1000_arr:
                        if alexa_domain in server_name or server_name in alexa_domain:
                            self.malware_alexa_ssl_aggregation += 1
                            break
                            # Check for unique
                    try:
                        if self.malware_same_connections_dict[dst_ip_and_src_ip]:
                            self.malware_same_connections_dict[dst_ip_and_src_ip] += 1
                    except:
                        self.malware_same_connections_dict[dst_ip_and_src_ip] = 1
                        for alexa_domain in self.alexa_1000_arr:
                            if alexa_domain in server_name or server_name in alexa_domain:
                                self.unique_malware_alexa_ssl_aggregation += 1
                                break


        ssl_file.close()

    '''
    Methods for adding not ssl flow from conn.log to connection-4tuple
    '''

    def conn_logs_2(self, dataset_path_to_logs):
        # print(" << Read all conn logs again:")
        all_conn_logs = get_such_logs(dataset_path_to_logs, ['conn', '_label'])
        for conn_log in all_conn_logs:
            self.add_not_ssl_logs(dataset_path_to_logs + conn_log)
        # print("     << Loaded conn logs 2: ", len(all_conn_logs))

    def add_not_ssl_logs(self, path_to_conn):
        # print("     <<< adding not ssl flow:")
        with open(path_to_conn) as f:
            for line in f:
                if '#' == line[0]:
                    continue
                conn_split = line.split('	')
                # 2-srcIpAddress, 4-dstIpAddress, 5-dstPort, 6-Protocol
                connection_index = conn_split[2], conn_split[4], conn_split[5], conn_split[6]
                try:
                    label = conn_split[21]
                except IndexError:
                    label = "False"
                conn_uid = conn_split[1]

                if 'Background' in label or 'No_Label' in label:
                    continue

                try:
                    if self.connection_4_tuples[connection_index]:
                        try:
                            if self.connection_4_tuples[connection_index].get_uid_flow_dict()[conn_uid]:
                                pass
                        except:
                            self.connection_4_tuples[connection_index].add_not_ssl_flow(line, label)
                except:
                    # Connections which are normal or botnet but they don't have ssl 4-tuple object.
                    pass
        f.close()

    """
    ------------------------------------------------
    --------------- Methods ------------------------
    ------------------------------------------------
    """

    '''
    Just checking function, that each x509uid from ssl log is found in x509 file.
    '''
    def split_ssl(self, ssl_line, tuple_index, label):
        split = ssl_line.split('	')
        if '-' == split[14] or '(object)' == split[14]:
            self.err_not_added_x509 += 1
            return []
        self.put_server_name_to_dict(split[1], split[9], tuple_index, split[14], label)
        return self.get_x509_lines(split[14].split(','))

    '''
    This function returns x509 line which ssl log has inside his line as list of uid.
    '''
    def get_x509_lines(self, x509_uids_list):
        x509_line = None
        uid_x509 = x509_uids_list[0]
        try:
            if self.x509_dict[uid_x509]:
                x509_line = self.x509_dict[uid_x509]
                self.founded_x509_lines += 1
        except:
            self.not_founded_x509_lines += 1
            return []
            # print "Error: [get_x509_lines] In ProcessLogs.py x509 does not have this x509uid:", x509_uids_list[0]
        return [x509_line]

    # certificate dict
    def put_server_name_to_dict(self, ssl_uid, server_name, tuple_index, x509_uids_list, label):
        splited_x509_uids = x509_uids_list.split(',')
        uid_x509 = splited_x509_uids[0]
        try:
            if self.x509_dict[uid_x509]:
                x509_line = self.x509_dict[uid_x509]
                x509_split = x509_line.split('	')
                cert_serial = x509_split[3]
                try:
                    if self.certificate_dict[cert_serial]:
                        self.certificate_dict[cert_serial].add_server_name(server_name, label)
                        self.certificate_dict[cert_serial].add_x509_line(x509_line)
                except:
                    self.certificate_dict[cert_serial] = CertificateFeatures(cert_serial, x509_line)
                    self.certificate_dict[cert_serial].add_server_name(server_name, label)
                    self.certificate_dict[cert_serial].add_x509_line(x509_line)
        except:
            # print("Error: [put_server_name] In ProcessLogs.py x509 does not have this x509uid:", uid_x509)
            pass


def get_such_logs(path_to_logs, part_name_list):
    searched_list = []
    for searched_file in os.listdir(path_to_logs):
        if all(x in searched_file for x in part_name_list):
            searched_list.append(searched_file)
    return searched_list

def load_root_cert():
    root_cert_arr = []
    with open("./trusted_root_certificates") as f:
        for line in f:
            root_cert_arr.append(line.rstrip())
    f.close()
    return root_cert_arr

def load_alexa_1000():
    alexa_1000_arr = []
    with open("./alexa_top_1000") as f:
        for line in f:
            alexa_1000_arr.append(line.rstrip())
    f.close()
    return alexa_1000_arr

