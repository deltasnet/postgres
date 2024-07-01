provider "aws" {
  region = "eu-west-1"
}

variable "key_name" {
  description = "Name of an existing EC2 KeyPair to enable SSH access to the instances"
  type        = string
  default     = PUTTY
}

resource "aws_vpc" "patroni_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "PatroniVPC"
  }
}

resource "aws_subnet" "main_subnet" {
  vpc_id            = aws_vpc.patroni_vpc.id
  availability_zone = data.aws_availability_zones.available.names[0]
  cidr_block        = "10.0.1.0/28"

  tags = {
    Name = "MainSubnet"
  }
}

resource "aws_subnet" "dr_subnet" {
  vpc_id            = aws_vpc.patroni_vpc.id
  cidr_block        = "10.0.2.0/28"
  availability_zone = data.aws_availability_zones.available.names[1]

  tags = {
    Name = "DRSubnet"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.patroni_vpc.id
}

resource "aws_route_table" "rt" {
  vpc_id = aws_vpc.patroni_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "RouteTable"
  }
}

resource "aws_route_table_association" "main_subnet_association" {
  subnet_id      = aws_subnet.main_subnet.id
  route_table_id = aws_route_table.rt.id
}

resource "aws_route_table_association" "dr_subnet_association" {
  subnet_id      = aws_subnet.dr_subnet.id
  route_table_id = aws_route_table.rt.id
}

resource "aws_security_group" "main_sg" {
  vpc_id = aws_vpc.patroni_vpc.id

  ingress {
    from_port   = 5400
    to_port     = 5400
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 8008
    to_port     = 8008
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 6400
    to_port     = 6400
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 2379
    to_port     = 2379
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 2380
    to_port     = 2380
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
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

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "MainSecurityGroup"
  }
}

resource "aws_iam_role" "main_ec2_role" {
  name = "MainEC2Role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "main_ec2_policy" {
  name   = "MainEC2Policy"
  role   = aws_iam_role.main_ec2_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeRegions"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "main_instance_profile" {
  name = "MainInstanceProfile"
  role = aws_iam_role.main_ec2_role.name
}

resource "aws_launch_configuration" "main_launch_config" {
  name            = "MainLaunchConfig"
  image_id        = "ami-0abcdef1234567890" # Replace with the correct RHEL 9 AMI ID
  instance_type   = "t2.small"
  iam_instance_profile = aws_iam_instance_profile.main_instance_profile.id
  security_groups = [aws_security_group.main_sg.id]
  key_name        = "your-key-name" # Replace with your SSH key name

  user_data = <<-EOF
              #!/bin/bash
              yum update -y
              yum install -y epel-release
              yum install -y postgresql-server patroni etcd haproxy pgbouncer
              # Create SSH directory and set permissions
              mkdir -p /home/ec2-user/.ssh
              chmod 700 /home/ec2-user/.ssh
              # Fetch the public key from the Ansible instance
              aws s3 cp s3://your-bucket-name/ansible_pub_key /home/ec2-user/.ssh/authorized_keys
              chmod 600 /home/ec2-user/.ssh/authorized_keys
              chown -R ec2-user:ec2-user /home/ec2-user/.ssh
              # Start and enable necessary services
              systemctl enable postgresql patroni etcd haproxy pgbouncer
              systemctl start postgresql patroni etcd haproxy pgbouncer
              EOF
}

resource "aws_autoscaling_group" "main_asg" {
  launch_configuration = aws_launch_configuration.main_launch_config.name
  min_size             = 6
  max_size             = 6
  desired_capacity     = 6
  vpc_zone_identifier  = [aws_subnet.main_subnet.id]
}

resource "aws_instance" "main_ansible" {
  instance_type          = "t2.medium"
  ami                    = "ami-0abcdef1234567890" # Replace with the correct RHEL 9 AMI ID
  subnet_id              = aws_subnet.main_subnet.id
  security_group_ids     = [aws_security_group.main_sg.id]
  key_name               = "your-key-name" # Replace with your SSH key name
  iam_instance_profile   = aws_iam_instance_profile.main_instance_profile.id

  user_data = <<-EOF
              #!/bin/bash
              yum update -y
              yum install -y ansible
              EOF
}

resource "aws_elb" "main_elb" {
  name               = "MainELB"
  subnets            = [aws_subnet.main_subnet.id]
  security_groups    = [aws_security_group.main_sg.id]

  listener {
    instance_port     = 6400
    instance_protocol = "TCP"
    lb_port           = 5000
    lb_protocol       = "TCP"
  }

  listener {
    instance_port     = 6400
    instance_protocol = "TCP"
    lb_port           = 5001
    lb_protocol       = "TCP"
  }

  listener {
    instance_port     = 6400
    instance_protocol = "TCP"
    lb_port           = 5002
    lb_protocol       = "TCP"
  }

  listener {
    instance_port     = 6400
    instance_protocol = "TCP"
    lb_port           = 5003
    lb_protocol       = "TCP"
  }
  
  health_check {
    target              = "TCP:8008"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }

  tags = {
    Name = "MainELB"
  }
}

data "aws_availability_zones" "available" {}
