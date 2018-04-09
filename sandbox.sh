#! /bin/sh
ulimit -n 65535

####### START SCRIPT CONFIGURATION #######

# Short description for the current service
DESC="Sandbox"

# Directory to run the daemon (this script will cd to it before launching the daemon),
# don't use the final slash!
DAEMON_DIR=/polyfalcon/analysis/sandbox

# Absolute path to the daemon script
DAEMON=$DAEMON_DIR/sandbox.py

# Path to the <machinemanager>.conf file
SANDBOX_KVM_CONF=$DAEMON_DIR/conf/kvm.conf

# Redirect the script's stderr output to this file (use /dev/null if you don't need it)
LOG_FILE=/polydata/log/sandbox_operation.log

# Arguments for the daemon, can be left empty or -d
DAEMON_ARGS=""

#Argument for clean sandbox
CLEAN_ARG="--clean"

# PID file to use to store the daemon's pid
PIDFILE=/var/run/sandbox.pid

# When stopping the daemon, wait MAX_SEC before forcing the kill with "kill -9"
MAX_SEC=10

####### END SCRIPT CONFIGURATION #######

check_status() {
    #echo 'check status'
    if [ -e $PIDFILE ]; then
        PID=$(cat $PIDFILE)
        kill -0 $PID >> $LOG_FILE 2>&1
        return $? # 0 if process is running, 1 if process is not running but pid file exists
    else
        return 3 # process is not running
    fi
}

start() {
    check_status
    STATUS=$?
    if [ $STATUS -eq 0 ]; then
        echo $DESC "is already running"
    else
        echo "Starting "$DESC"..."

        cd $DAEMON_DIR

        # Destroy machines used by Sandbox
        for vm in $(grep -e "^machines\s*=.*" $SANDBOX_KVM_CONF | cut -d '=' -f 2 | sed 's/,/ /g'); do
            if [ $(virsh domstate $vm | grep "shut off" | wc -l) -eq 0 ]; then
                virsh destroy $vm >> $LOG_FILE 2>&1
            fi
        done

        # Start process
        python $DAEMON $DAEMON_ARGS > /dev/null 2>&1 &
        PID=$!
        echo $PID > $PIDFILE
        kill -0 $PID >> $LOG_FILE 2>&1
        if [ $? -eq 0 ]; then
            echo "... done!"
        else
            echo ">>> ERROR STARTING PROCESS! <<<"
        fi
    fi
}

stop() {
        #check_status
        process_count=$(ps aux|grep sandbox.py |grep -v grep|wc -l)
        #STATUS=$?
        #if [ $STATUS -eq 0 ]; then
        if [ $process_count -gt 0 ]; then
            echo "python $DAEMON --notifyclose"
            python $DAEMON --notifyclose
            echo "Stopping "$DESC"..."
#            PID=$(cat $PIDFILE)
#            kill $PID >> $LOG_FILE 2>&1
#            i=0
#            while [ $i -lt $MAX_SEC ]; do
#                sleep 1
#                i=$(expr $i + 1)
#                kill -0 $PID >> $LOG_FILE 2>&1
#                if [ $? -eq 1 ]; then
#                    rm -f $PIDFILE
#                    echo "... done!"
#                    return
#                fi
#            done
#            kill -9 $PID >> $LOG_FILE 2>&1
#            echo "... done! (forced stop after "$MAX_SEC" seconds)"
            rm -f $PIDFILE
        else
            echo $DESC "was already stopped"
            if [ -e $PIDFILE ]; then
                rm -f $PIDFILE
            fi
        fi
}

clean() {
    echo 'clean sandbox started...'
    echo 'stop sandbox instance first...'
    stop
    sleep 2
    cd $DAEMON_DIR
    python $DAEMON $CLEAN_ARG > /dev/null 2>&1 &
    rm -f $LOG_FILE
    echo 'clean sandbox ended...'
}

wait_for_process_exit()
{
	process_count=$(ps aux|grep sandbox.py |grep -v grep|wc -l)
	
    while [ $process_count -gt 0 ]; do
        sleep 1
    done
    
    echo "process is not existed now!"
}

case "$1" in
  start)
    start
	;;
  stop)
    stop
	;;
  restart)
    stop
    wait_for_process_exit
    start
	;;
  clean)
    clean
	;;
  status)
    check_status
    STATUS=$?
    if [ $STATUS -eq 0 ]; then
        echo $DESC "is running"
    elif [ $STATUS -eq 1 ]; then
        echo $DESC "is not running but pid file exists"
    else
        echo $DESC "is not running"
    fi
    ;;
  *)
	echo "Usage: aptcmp sandbox {start|stop|restart|clean|status}"
    exit
	;;
esac
