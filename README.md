# Provision and Microservice on AWS

Practices deployment of application tier via terraform.

## Create basic Flask API 
* This will create an api endpoint that can be connected to to access the song database that stores data in dynamodb
* Docker container to be built and deployed to ECS by Terraform

## Terraform code to deploy infrastructure
* VPC infrastructure 
* Container infra on ECS
* DynamoDB table
* IAM roles
* Security groups
* Some other trimmings such as basic cloudwatch metrics

# Todo
* Build out deployment pipeline with github actions
* Investigate Terraform native testing in version 2.
* Review usage of codedeploy / pipelines and add tfsec or OPA policies
* Review deployment using Gitlab / with view to move from ECS to EKS (and perhaps use Argo)
* Do deployment of code to Lambda behind API gateway
* Create nextjs front end (time allows lets do OAuth integration etc)