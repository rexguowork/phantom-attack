#!/usr/bin/env python
import os
import subprocess
import time
import threading
import signal
import sys
from sh import tail

class fileArtifacts:
    '''
    store files:
    good_file: this is what we want sysdig to believe
    bad_filename: this is what we want kernel to execute

    sanity_failure: both fake and bad file are generated
    impossible_scenario: sysdig report bad, syscall open fake
    '''
    def __init__(self, bad_filename, fake_filename):       
        # store deposit address of the user
        self.bad_filename = bad_filename
        # store the list of target address of the user
        self.fake_filename = fake_filename
        # delay
        self.delay = 0
        self.success = 0
        self.failure = 0
        self.no_harm = 0
        self.sanity_failure = 0
        self.impossible_scenario = 0

    def set_delay(self, delay):
        self.delay = delay

    def reset(self):
        self.success = 0
        self.failure = 0
        self.no_harm = 0
        self.sanity_failure = 0
        self.impossible_scenario = 0

    def print(self):
        print("success = %d, failure = %d,\
                no_harm = %d, impossible_scenario = %d" % (
                self.success, self.failure,\
                self.no_harm, self.impossible_scenario));


class status:
    '''
    stores the four attributes we track
    '''
    def __init__(self):       
        self.has_bad_file = 0
        self.has_fake_file = 0
        self.report_bad_file = 0
        self.report_fake_file = 0

    def print(self):
        print("has_bad_file = %d, has_fake_file = %d,\
                report_bad_file = %d, report_fake_file = %d" % (
                self.has_bad_file, self.has_fake_file,\
                self.report_bad_file, self.report_fake_file));


def remove(filename):
    if os.path.isfile(filename):
        os.remove(filename)


def clean_file(fa):
    '''
    remove artifacts files
    '''
    remove(fa.bad_filename)
    remove(fa.fake_filename)


def wait_check_clean(fa, stat):
    while not os.path.isfile(fa.bad_filename) and not os.path.isfile(fa.fake_filename):
        time.sleep(0.05)
    count_file(fa, stat)
    clean_file(fa)

def wait_file(filename):
    while not os.path.isfile(filename):
        time.sleep(0.05)

def wait_file_not_empty(filename):
    wait_file(filename)
    while os.stat(filename).st_size == 0:
        time.sleep(0.1)


def count_file(artifacts, stat):
    '''
    provide statistics
    '''
    if os.path.isfile(artifacts.bad_filename):
        stat.has_bad_file += 1 
    if os.path.isfile(artifacts.fake_filename):
        stat.has_fake_file += 1

def sanity_check(fa, stat):
    count = 0
    if stat.has_bad_file:
        count += 1
    if stat.has_fake_file:
        count += 1 
    if stat.report_bad_file:
        count += 1 
    if stat.report_fake_file:
        count += 1
    if count > 2:
        print("has_bad_file = %r, has_fake_file = %r, report_bad_file = %r,\
                report_fake_file = %r\n" % (stat.has_bad_file,\
                    stat.has_fake_file, stat.report_bad_file,\
                    stat.report_fake_file))
        fa.sanity_failure += 1
        #sys.exit("sanity_check error")

def compute_metrics(fa, stat):
    '''
    We compute metrics after aggregation

    actual    report     result
    bad_f     fake       success
    bad_b     bad        failure
    fake      fake       no_harm
    fake      bad        impossible  (we consider this cannot happen)
    '''
    fa.no_harm = stat.has_fake_file
    fa.failure = stat.report_bad_file
    bad_b = stat.report_bad_file
    bad_f = stat.has_bad_file - bad_b
    fa.success = bad_f

    '''
    # this is metrics if we compare sysdig log and file generation event per
    # attack run
    sanity_check(fa, stat)
    if stat.has_bad_file and stat.report_bad_file:
        fa.failure += 1 
    elif stat.has_bad_file and stat.report_fake_file:
        fa.success += 1 
    elif stat.has_fake_file and stat.report_fake_file:
        fa.no_harm += 1 
    elif stat.has_fake_file and stat.report_bad_file:
        fa.impossible_scenario += 1
        #sys.exit("compute_metrics shouldn't reach here!")
    '''
def get_sysdig_result(sysdig_log_name, fa, stat):
    f = open(sysdig_log_name, 'r')
    while True:
        line = f.readline()
        if fa.bad_filename in line:
            stat.report_bad_file += 1 
        elif fa.fake_filename in line:
            stat.report_fake_file += 1
        if not line:
            break
    f.close()


def chdir(path):
    try:
        os.chdir(path)
        print("Current working directory: {0}".format(os.getcwd()))
    except FileNotFoundError:
        print("Directory: {0} does not exist".format(path))
    except NotADirectoryError:
        print("{0} is not a directory".format(path))
    except PermissionError:
        print("You do not have permissions to change to {0}".format(path))


def runsysdig():
    '''
    run sysdig as a separate process

    TODO: 
    it will be a nice practice to have python thread to handle this
    '''
    cwd = os.getcwd()
    #print(cwd)
    sysdig_path = "/home/sysdig/security-research/sysdig/build"
    chdir(sysdig_path)
    command = "sysdigsyscall openat attack_openat > /tmp/sysdig.log"
    p = subprocess.Popen(["/bin/bash", "-i", "-c", command])
    print("sysdig runs")
    chdir(cwd)
    return p


def killsysdig(p):
    '''
    takes sysdig process handle p and kill the process
    '''
    while p.poll() is None:
        print('Sysdig still running')
        ps = subprocess.Popen(['ps', '-A'], stdout=subprocess.PIPE)
        output, error = ps.communicate()
        #print(output)
        target_process = "sysdig"
        for line in output.splitlines():
            if target_process in str(line):
                pid = int(line.split(None, 1)[0])
                #os.kill(pid, 9)
                subprocess.run(["sudo", "kill", "-9", str(pid)])
        time.sleep(0.00001)
    print("sysdig killed")


def main():
    '''
    for each delay:
      for 1000 experiments:
        clean bad_filename, fake_filename
        run experiment with delay
         check which file is created, get total count
    
    check which file is reported by sysdig, get total count
    compute total success rate per delay

    '''
    #delay_start = 2400
    #delay_end   = 2500
    delay_start = 0 
    delay_end   = 1

    step        =  10
    num_experiments = 15 
    bad_filename = "malicious_file"
    fake_filename = "benign_file"
    
    sysdig_log_name = "/tmp/sysdig.log"    
    # start monitoring thread
    # dont be fancy, use simple and easy synchronization

    # start tail
    #tail_sysdig = tail("-f", sysdig_log_name, _iter=True)

    # record result
    res_name = "results.txt"
    remove(res_name)
    res_file = open(res_name, 'a')
    fa = fileArtifacts(bad_filename, fake_filename)
    clean_file(fa)
    lines = None
    # each delay is 1 ns
    for d in range(delay_start, delay_end+1, step):
        fa.set_delay(d) 
        stat = status()
        remove(sysdig_log_name)
        sysdigp = runsysdig()
        wait_file(sysdig_log_name)
        time.sleep(1)
        for i in range(num_experiments):
            subprocess.run(["sudo", "./attack_openat", str(d)])
            wait_check_clean(fa, stat)                     
        '''
        self.bad_count = 0
        # count of fake files created
        self.fake_count = 0
        # count of bad files reported by sysdig
        self.bad_report_count = 0
        # count of fake files reported by sysdig
        self.fake_report_count = 0
        self.success = 0
        self.failure = 0
        self.win_rate = 0
        '''
        time.sleep(0.1)
        killsysdig(sysdigp)
        get_sysdig_result(sysdig_log_name, fa, stat)
        compute_metrics(fa, stat)
        if fa.success + fa.failure != 0:
            fa.win_rate = fa.success / float(fa.success + fa.failure)       
        else:  # -1 means not applicable
            fa.win_rate = -1

        print("delay = %d, success = %d, failure = %d,\
                no_harm = %d, impossible_scenario = %d, win_rate = %f" % (d, \
                fa.success, fa.failure,\
                fa.no_harm, fa.impossible_scenario, fa.win_rate));
        res_file.write("delay = %d, success = %d, failure = %d,\
                no_harm = %d, impossible_scenario = %d, win_rate = %f\n" % (d, \
                fa.success, fa.failure,\
                fa.no_harm, fa.impossible_scenario, fa.win_rate));

    # final clean up


if __name__=="__main__":
    main()
