provider "aws" {
  region = "eu-west-1"
}

variable "key_name" {
  description = "Name of an existing EC2 KeyPair to enable SSH access to the instances"
  type        = string
  default     = PUTTY
}

variable "vpc_cidr" {
  description = "IP range for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "main_subnet_cidr" {
  description = "IP range for the main Patroni cluster subnet"
  type        = string
  default     = "10.0.1.0/28"
}

variable "dr_subnet_cidr" {
  description = "IP range for the DR Patroni cluster subnet"
  type        = string
  default     = "10.0.2.0/28"
}

resource "aws_vpc" "patroni_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "PatroniVPC"
  }
}

resource "aws_subnet" "main_subnet" {
  vpc_id            = aws_vpc.patroni_vpc.id
  availability_zone = data.aws_availability_zones.available.names[0]
  cidr_block        = var.main_subnet_cidr

  tags = {
    Name = "MainSubnet"
  }
}

resource "aws_subnet" "dr_subnet" {
  vpc_id            = aws_vpc.patroni_vpc.id
  availability_zone = data.aws_availability_zones.available.names[1]
  cidr_block        = var.dr_subnet_cidr

  tags = {
    Name = "DRSubnet"
  }
}

resource "aws_internet_gateway" "patroni_igw" {
  vpc_id = aws_vpc.patroni_vpc.id
}

# Create route table
resource "aws_route_table" "public_route_table" {
  vpc_id = aws_vpc.patroni_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.patroni_igw.id
  }

  tags = {
    Name = "PublicRouteTable"
  }
}

# Associate subnets with route table
resource "aws_route_table_association" "main_subnet_association" {
  subnet_id      = aws_subnet.main_subnet.id
  route_table_id = aws_route_table.public_route_table.id
}

resource "aws_route_table_association" "dr_subnet_association" {
  subnet_id      = aws_subnet.dr_subnet.id
  route_table_id = aws_route_table.public_route_table.id
}

# Create security groups
resource "aws_security_group" "db_security_group" {
  name        = "DBSecurityGroup"
  description = "Security group for DB instances"
  vpc_id      = aws_vpc.patroni_vpc.id

  ingress {
    from_port       = 5400
    to_port         = 5400
    protocol        = "tcp"
    self            = true
  }

  ingress {
    from_port       = 8008
    to_port         = 8008
    protocol        = "tcp"
    self            = true
  }

  ingress {
    from_port       = 6400
    to_port         = 6400
    protocol        = "tcp"
    self            = true
  }

  ingress {
    from_port       = 2379
    to_port         = 2379
    protocol        = "tcp"
    security_groups = [aws_security_group.etcd_security_group.id]
  }
}

resource "aws_security_group" "etcd_security_group" {
  name        = "ETCDSecurityGroup"
  description = "Security group for ETCD instances"
  vpc_id      = aws_vpc.patroni_vpc.id

  ingress {
    from_port       = 2379
    to_port         = 2379
    protocol        = "tcp"
    security_groups = [aws_security_group.db_security_group.id]
  }

  ingress {
    from_port       = 2380
    to_port         = 2380
    protocol        = "tcp"
    self            = true
  }
}

resource "aws_security_group" "haproxy_security_group" {
  name        = "HAProxySecurityGroup"
  description = "Security group for HAProxy instances"
  vpc_id      = aws_vpc.patroni_vpc.id

  ingress {
    from_port       = 8008
    to_port         = 8008
    protocol        = "tcp"
    security_groups = [aws_security_group.db_security_group.id]
  }

  ingress {
    from_port   = 5000
    to_port     = 5005
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 7000
    to_port     = 7000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "ansible_security_group" {
  name        = "AnsibleSecurityGroup"
  description = "Security group for Ansible instances"
  vpc_id      = aws_vpc.patroni_vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Create IAM roles and instance profiles
resource "aws_iam_role" "db_role" {
  name = "DBRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  managed_policy_arns = ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]
}

resource "aws_iam_instance_profile" "db_instance_profile" {
  name = "DBInstanceProfile"
  role = aws_iam_role.db_role.name
}

resource "aws_iam_role" "etcd_role" {
  name = "ETCDRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  managed_policy_arns = ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]
}

resource "aws_iam_instance_profile" "etcd_instance_profile" {
  name = "ETCDInstanceProfile"
  role = aws_iam_role.etcd_role.name
}

resource "aws_iam_role" "ansible_role" {
  name = "AnsibleRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  managed_policy_arns = ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]
}

resource "aws_iam_instance_profile" "ansible_instance_profile" {
  name = "AnsibleInstanceProfile"
  role = aws_iam_role.ansible_role.name
}

# Create launch templates
resource "aws_launch_template" "main_db_launch_template" {
  name = "MainDBLaunchTemplate"

  image_id      = "ami-0ba62214afa52bec7"  # RHEL 9 AMI
  instance_type = "t2.small"
  key_name      = var.key_name

  iam_instance_profile {
    name = aws_iam_instance_profile.db_instance_profile.name
  }

  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.db_security_group.id]
  }
}

resource "aws_launch_template" "dr_db_launch_template" {
  name = "DRDBLaunchTemplate"

  image_id      = "ami-0ba62214afa52bec7"  # RHEL 9 AMI
  instance_type = "t2.small"
  key_name      = var.key_name

  iam_instance_profile {
    name = aws_iam_instance_profile.db_instance_profile.name
  }

  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.db_security_group.id]
  }
}

resource "aws_launch_template" "main_etcd_launch_template" {
  name = "MainETCDLaunchTemplate"

  image_id      = "ami-0ba62214afa52bec7"  # RHEL 9 AMI
  instance_type = "t2.small"
  key_name      = var.key_name

  iam_instance_profile {
    name = aws_iam_instance_profile.etcd_instance_profile.name
  }

  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.etcd_security_group.id, aws_security_group.haproxy_security_group.id]
  }
}

resource "aws_launch_template" "dr_etcd_launch_template" {
  name = "DRETCDLaunchTemplate"

  image_id      = "ami-0ba62214afa52bec7"  # RHEL 9 AMI
  instance_type = "t2.small"
  key_name      = var.key_name

  iam_instance_profile {
    name = aws_iam_instance_profile.etcd_instance_profile.name
  }

  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.etcd_security_group.id, aws_security_group.haproxy_security_group.id]
  }
}

resource "aws_launch_template" "ansible_launch_template" {
  name = "AnsibleLaunchTemplate"

  image_id      = "ami-0ba62214afa52bec7"  # RHEL 9 AMI
  instance_type = "t2.medium"
  key_name      = var.key_name

  iam_instance_profile {
    name = aws_iam_instance_profile.ansible_instance_profile.name
  }

  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.ansible_security_group.id]
  }
}

# Create EC2 instances
resource "aws_instance" "main_db_instances" {
  count = 3

  launch_template {
    id      = aws_launch_template.main_db_launch_template.id
    version = "$Latest"
  }

  subnet_id = aws_subnet.main_subnet.id

  tags = {
    Name = "MainDBInstance${count.index + 1}"
  }
}

resource "aws_instance" "dr_db_instances" {
  count = 3

  launch_template {
    id      = aws_launch_template.dr_db_launch_template.id
    version = "$Latest"
  }

  subnet_id = aws_subnet.dr_subnet.id

  tags = {
    Name = "DRDBInstance${count.index + 1}"
  }
}

resource "aws_instance" "main_etcd_instances" {
  count = 3

  launch_template {
    id      = aws_launch_template.main_etcd_launch_template.id
    version = "$Latest"
  }

  subnet_id = aws_subnet.main_subnet.id

  tags = {
    Name = "MainETCDInstance${count.index + 1}"
  }
}

resource "aws_instance" "dr_etcd_instances" {
  count = 3

  launch_template {
    id      = aws_launch_template.dr_etcd_launch_template.id
    version = "$Latest"
  }

  subnet_id = aws_subnet.dr_subnet.id

  tags = {
    Name = "DRETCDInstance${count.index + 1}"
  }
}

resource "aws_instance" "ansible_instance_main" {
  launch_template {
    id      = aws_launch_template.ansible_launch_template.id
    version = "$Latest"
  }

  subnet_id = aws_subnet.main_subnet.id

  tags = {
    Name = "AnsibleInstanceMain"
  }
}

resource "aws_instance" "ansible_instance_dr" {
  launch_template {
    id      = aws_launch_template.ansible_launch_template.id
    version = "$Latest"
  }

  subnet_id = aws_subnet.dr_subnet.id

  tags = {
    Name = "AnsibleInstanceDR"
  }
}

# Create Elastic IPs
resource "aws_eip" "main_etcd_eip" {
  vpc = true
}

resource "aws_eip_association" "main_etcd_eip_association" {
  instance_id   = aws_instance.main_etcd_instances[0].id
  allocation_id = aws_eip.main_etcd_eip.id
}

resource "aws_eip" "dr_etcd_eip" {
  vpc = true
}

resource "aws_eip_association" "dr_etcd_eip_association" {
  instance_id   = aws_instance.dr_etcd_instances[0].id
  allocation_id = aws_eip.dr_etcd_eip.id
}