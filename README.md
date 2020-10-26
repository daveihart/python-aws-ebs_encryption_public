# python-aws-ebs_encryption
Encrypt EBS volumes which are unencrypted targeting instances by tag

Testing in Python virtual environment using python version 3.8 on Ubuntu 20.04 on WSL2

## Getting Started

### Virtual environment
- python3.8 -m venv env
- source env/bin/activate
- pip install --upgrade pip
- pip install --upgrade boto3
- pip install --upgrade awscli


### Environment Variables
To ensure the code can easily be re-used I have set all the key elements as variables. These can also be defined as variables in any automation software.

Key                  | Value
---------------------|----------------------
verbose | True or False - if True you will get a lot of output!
search_tag | Tag to search for instances, e.g. Name
search_value | Value in search_tag to search for instances
snap_prefix | Snapshot description
arole | Role to assume across accounts
accounts | list of accounts to process using above role e.g ['0000000000000','1111111111111','2222222222222222','333333333333333333']

## Process Flow
1. For each account listed
2. Retrieve instance details from instances which fulfil the filter rules based on tag
3. For each instance
4. Check for unencrypted volumes
5. Shutdown if unencrypted volumes exist and state was running
6. Detach volume
7. Create unencrypted snapshot
8. Create encrypted copy of snapshot
9. Create encrypted volume of snapshot
10. Attach encrypted volumes
11. Return machine to original state

### Known issues
None

### Completed enhancements
1. Setup to use tags instead of input file
2. Setup to use a role rather than AWS CLI credentials.
3. Configure to use an array of accounts.
4. remove the counts and instead use the cli wait commands (new post code writing)
5. Rewrite in python

### Planned enhancements
None presently

## Author
**Dave Hart**
[link to blog!](https://davehart.co.uk)