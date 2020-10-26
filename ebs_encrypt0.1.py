#!/usr/bin/env python3.6

import botocore
import boto3
from boto3.session import Session
from botocore.exceptions import ClientError
import time
import os
from datetime import date
#import json

dt=date.today()
dtstr=dt.strftime("%Y-%m-%d")

search_tag = "some_key_name" # Tag to search for instances
search_value = "some_key_value"  #value in tag to search for instances 
snap_prefix = dtstr+"-post_encryption-snapshot" #snapshot description
arole="AddARoleHere" #role to assume across accounts
accounts = ['AWS Accounts Here', 'Another AWS Account here'] # list of accounts e.g ['0000000000000','1111111111111','2222222222222222','333333333333333333']
total_acc = len(accounts)
region = "eu-west-2"
verbose = True

if verbose:
    print(f"{total_acc} AWS account(s) detected")

def assume_roles(acc,accounts,arole):
    global acc_key
    global sec_key
    global sess_tok
    global client
    if verbose:
        print(f"Assuming role")
    sts_conn = boto3.client('sts')
    tmp_arn = f"{acc}:role/{arole}"
    response = sts_conn.assume_role(DurationSeconds=900,RoleArn=f"arn:aws:iam::{tmp_arn}",RoleSessionName='Test')
    acc_key = response['Credentials']['AccessKeyId']
    sec_key = response['Credentials']['SecretAccessKey']
    sess_tok = response['Credentials']['SessionToken']
    
def get_instances(process_acc,filters=[{'Name': 'tag:'+search_tag, 'Values': [search_value]}]):
    reservations = {}
    try:
        reservations = ec2.describe_instances(
            Filters=filters
        )
    except botocore.exceptions.ClientError as e:
        print(e.response['Error']['Message'])
    instances = []
    for reservation in reservations.get('Reservations', []):
        for instance in reservation.get('Instances', []):
            instances.append(instance)
    return instances 

def process_instance(Iname):
    global volatt
    global volid
    global tags_list
    global Istate
    global IstateCode
    processed_status = "no"
    Istate = inst.get('State')
    IstateCode = Istate.get('Code')
    get_status(Iid)
    if verbose:
        print(f"Instance Name : {Iname} ; Instance Id : {Iid[0]} ; Instance state : {IstateCode}")
        print(f"Checking volumes attached to {Iid[0]} for encryption settings")
    vols = ec2.describe_volumes(
        Filters=[
        {
            'Name': 'attachment.instance-id',
            'Values': [
                str(Iid[0]),
           ],
        },
        ],
    )
    x = 0
    for dev in vols.get('Volumes'):
        x = x +1
        if verbose:
            print(f"processing volume : {x}")
        try:
            att = dev.get("Attachments")
            encstatus = dev.get('Encrypted')
            volid = dev.get ('VolumeId')
            if verbose:
                print(f"volumeid :      {volid}")
                print(f"attachment :    {att}")
            volatt = att[0].get('Device')
            if encstatus == False:
                if verbose:
                    print(f"Volume will need to be encrypted")
                if initial_status == "running" and processed_status == "no":
                    if verbose:
                        print(f"shutting down {Iid[0]}")
                    shutdown_instance(Iid)
                    processed_status = "yes"
                tags_list = dev.get('Tags', [])
                moveon="no"
                while not Iid[0] in FailedIid and moveon == "no":
                    detach_old_ebs()
                    snapshot_volumes()
                    snapshot_copy()
                    create_ebs()
                    attach_new_ebs()
                    set_delete_terminate()
                    delete_ebs()
                    moveon="yes"
            else:
                if verbose:
                    print(f"{volid} is already encrypted")
        except botocore.exceptions.ClientError as er:
            print("error on check_volumes")
            print(er.response['Error']['Message'])
            FailedIid.append(Iid[0])
    if initial_status == "running":
        if verbose:
            print(f"starting instance {Iid[0]}")
        start_instance(Iid)
    else:
        if not Iid[0] in FailedIid: # it did not fail but was stopped to begin with
            SuccessIid.append(Iid[0])
    

def get_status(Iid):
    global initial_status
    if IstateCode == 16 or IstateCode ==32 or IstateCode == 64 or IstateCode == 80:
        if IstateCode == 16:
            initial_status = "running"
        elif IstateCode == 32 or IstateCode == 64:
            initial_status = "shutting_down"
        elif IstateCode == 80:
            initial_status = "stopped"
    else:
            print(f"Warning : Instance {Iid[0]} is not running, stopping or stopped. Please perform a manual check")
            initial_status = "not_sure"
            FailedIid.append(Iid[0])
    return initial_status

def shutdown_instance(Iid):
    try:
        ec2.stop_instances(InstanceIds=Iid)
        shutdown_instance_wait(Iid,initial_status)
    except botocore.exceptions.ClientError as er:
        print(er.message)
        print("error on shutdown_instance")
        FailedIid.append(Iid[0])

def create_snapshots_wait(snap_shot):
    global snap_check
    snap_check = []
    snap_check.append(snap_shot.get('SnapshotId'))
    try:
        create_snapshot_waiter = ec2.get_waiter('snapshot_completed')
        if verbose:
            print(f"Waiting for {snap_check[0]}")
        create_snapshot_waiter.wait(SnapshotIds=snap_check)  
    except botocore.exceptions.WaiterError as er:
        if "Max attempts exceeded" in er.message:
            print("error on create_snapshots_wait")
            print(f"Instance {Iid[0]} did not shutdown in 600 seconds")
            FailedIid.append(Iid[0])
        else:
            print("error on create_snapshots_wait_else")
            print(er.message)
            FailedIid.append(Iid[0])


def shutdown_instance_wait(Iid,initial_status):
    shutdown_instance_waiter = ec2.get_waiter('instance_stopped')
    try:
        shutdown_instance_waiter.wait(InstanceIds=Iid)
        if verbose:
            print(f"Instance {Iid[0]} has shutdown successfully")
    except botocore.exceptions.WaiterError as er:
        if "Max attempts exceeded" in er.message:
            print("error on shutdown_instance_wait")
            print(f"Instance {Iid[0]} did not shutdown in 600 seconds")
            FailedIid.append(Iid[0])
        else:
            print("error on shutdown_instance_wait_else")
            print(er.message)
            FailedIid.append(Iid[0])
    return initial_status

def start_instance(Iid):
    try:
        ec2.start_instances(InstanceIds=Iid)
        SuccessIid.append(Iid[0])
    except botocore.exceptions.ClientError as er:
        print("error on start_instance")
        print(er.response['Error']['Message'])
        FailedIid.append(Iid[0])

def snapshot_volumes():
    global snap_shot
    global unenc_snapshot
    try:
        snap_shot = ec2.create_snapshot(
            VolumeId=volid,
            Description=snap_prefix,
            TagSpecifications=[
                {
                'ResourceType' : 'snapshot',
                'Tags': tags_list,      
                }
            ],
        )
        create_snapshots_wait(snap_shot)
        unenc_snapshot = snap_shot.get('SnapshotId')
        if verbose:
            print(f"Unencrypted snapshot : {unenc_snapshot}")
    except botocore.exceptions.ClientError as er:
        print("error on snapshot_volumes")
        print(er.response['Error']['Message'])
        FailedIid.append(Iid[0])

def snapshot_copy():
    global enc_snapshot
    try:
        snap_shot = ec2.copy_snapshot(
        Description="encrypted-"+snap_prefix,
        TagSpecifications=[
                {
                'ResourceType' : 'snapshot',
                'Tags': tags_list,      
                }
            ],  
        Encrypted=True,
        SourceRegion=region,
        SourceSnapshotId=snap_check[0],
        )
        enc_snapshot = snap_shot.get('SnapshotId')
        create_snapshots_wait(snap_shot)
        if verbose:
            print(f"encrypted snapshot : {enc_snapshot}")
    except botocore.exceptions.ClientError as er:
        print("error on snapshot_copy")
        print(er.response['Error']['Message'])
        FailedIid.append(Iid[0])
    ec2.delete_snapshot(SnapshotId=unenc_snapshot,
    )

def create_ebs():
    global enc_ebs_id
    try:
        enc_ebs = ec2.create_volume(
        AvailabilityZone=az2,
        Encrypted=True,
        SnapshotId=enc_snapshot,
        TagSpecifications=[
                {
                'ResourceType' : 'volume',
                'Tags': tags_list,      
                }
            ],
        )
        enc_ebs_id = enc_ebs.get('VolumeId')
        ebs_wait = enc_ebs_id
        create_ebs_wait()
    except botocore.exceptions.ClientError as er:
        print("error on create_ebs")
        print(er.message)
        FailedIid.append(Iid[0])

def create_ebs_wait():
    global ebs_check
    ebs_check = []
    ebs_check.append(ebs_wait)
    try:
        create_ebs_available_waiter = ec2.get_waiter('volume_available')
        create_ebs_available_waiter.wait(VolumeIds=ebs_check)  
        time.sleep(5)
    except botocore.exceptions.WaiterError as er:
        if "Max attempts exceeded" in er.message:
            print(f"Volume {enc_ebs_id} was not available in the max wait time")
        else:
            print("error on create_ebs_wait")
            print(er.message)
            FailedIid.append(Iid[0])    
    
def volume_in_use_wait():
    global ebs_check
    ebs_check = []
    ebs_check.append(ebs_wait)
    try:
        create_ebs_available_waiter = ec2.get_waiter('volume_in_use')
        create_ebs_available_waiter.wait(VolumeIds=ebs_check)
    except botocore.exceptions.WaiterError as er:
        if "Max attempts exceeded" in er.message:
            print(f"Volume {enc_ebs_id} was not available in the max wait time")
        else:
            print("error on volume_in_use_wait")
            print(er.message)
            FailedIid.append(Iid[0])

def detach_old_ebs():
    try:
        global ebs_wait
        detach_ebs = ec2.detach_volume(
        Device=volatt,
        InstanceId=Iid[0],
        VolumeId=volid,
        )
        if verbose:
            print(f"Waiting for volume {volid} to be detached")
        ebs_wait = volid
        create_ebs_wait()
    except botocore.exceptions.ClientError as er:
        print("error on detach_old_ebs")
        print(er.response['Error']['Message'])
        FailedIid.append(Iid[0])

def attach_new_ebs():
    try:
        if verbose:
            print(f"Attaching volume {enc_ebs_id} to {volatt}")
        attach_ebs = ec2.attach_volume(
        Device=volatt,
        InstanceId=Iid[0],
        VolumeId=enc_ebs_id,
        )
    except botocore.exceptions.ClientError as er:
        print("error on attach_new_ebs")
        print(er.response['Error']['Message'])
        FailedIid.append(Iid[0])

def set_delete_terminate():
    if verbose:
        print(f"deleteontermination check : {enc_ebs_id}")
    delonterm = ec2.modify_instance_attribute(
    Attribute='blockDeviceMapping',
    BlockDeviceMappings=[
    {
    'DeviceName': volatt,
    'Ebs': {
    'DeleteOnTermination': True,
    }}],
    InstanceId=Iid[0])

def delete_ebs():
    try:
        delete_ebs = ec2.delete_volume(
            VolumeId=volid
        )
    except botocore.exceptions.ClientError as er:
        print("error on delete_ebs")
        print(er.response['Error']['Message'])
        FailedIid.append(Iid[0])

def main():
    global ec2
    global instances
    global az2
    global Iid
    global inst
    global FailedIid
    global SuccessIid
    processing_acc = 0
    FailedIid = []
    SuccessIid = []
    client = boto3.client("sts")
    account_id = client.get_caller_identity()["Account"]
    if verbose:
        print(f"script is executing in {account_id}")
    for acc in accounts:
        processing_acc += 1
        if verbose:
            print(f"Processing account : {processing_acc}")
        if acc != account_id:
            assume_roles(acc,accounts,arole)
            ec2 = boto3.client('ec2',aws_access_key_id=acc_key,aws_secret_access_key=sec_key,aws_session_token=sess_tok,region_name='eu-west-1')
        else:
            if verbose:
                print(f"Execution account, no assume required")
            ec2=boto3.client('ec2')
        instances = get_instances(processing_acc)
        for inst in instances:
            try:
                az=inst.get("Placement")
                az2=az.get("AvailabilityZone")
                Iid = []
                Iid.append(inst.get('InstanceId'))
                #The for and first if can be removed, used to retrieve the name tag for verbose output
                for tags in inst.get('Tags'):
                    if tags["Key"] == 'Name':
                        Iname = tags["Value"]
                        process_instance(Iname)
                print("-------------------------------------------------------------------------")
            except botocore.exceptions.ClientError as er:
                print("error on main")
                print(er.response['Error']['Message'])
                FailedIid.append(Iid[0])
                continue
    print(f"Errors encountered with these instances: {FailedIid}")
    print(f"Successfully processed these instances: {SuccessIid}")

if __name__ == "__main__":
    main()
