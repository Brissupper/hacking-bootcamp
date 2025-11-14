provider "aws" {
  region = "us-east-1"
}

resource "random_id" "bucket" {
  byte_length = 4
}

resource "aws_s3_bucket" "misconfig_bucket" {
  bucket = "misconfig-sim-${random_id.bucket.hex}"
}

resource "aws_s3_bucket_acl" "misconfig_acl" {
  bucket = aws_s3_bucket.misconfig_bucket.id
  acl    = "public-read"
}

resource "aws_iam_user" "weak_user" {
  name = "weakuser"
}

resource "aws_iam_user_policy" "over_priv" {
  user = aws_iam_user.weak_user.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role" "assume_role" {
  name = "AssumeMeRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = { "AWS": "arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/weakuser" }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "admin_attach" {
  role       = aws_iam_role.assume_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

data "aws_caller_identity" "current" {}

resource "aws_security_group" "vuln_sg" {
  name        = "vuln-sg"
  description = "Misconfigured SG"
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "vuln_instance" {
  ami                         = "ami-0c55b159cbfafe1d0"
  instance_type               = "t2.micro"
  security_groups             = [aws_security_group.vuln_sg.name]
  key_name                    = aws_key_pair.vuln_key.key_name
  associate_public_ip_address = true
  tags = {
    Name = "VulnInstance"
  }
}

resource "aws_key_pair" "vuln_key" {
  key_name   = "vuln-key"
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC..."  # Replace with your real pub key
}
