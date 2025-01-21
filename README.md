# terragrunt-project-template
Terraform Project Build Automation Template
* Prerequisites:
  * AWS
    * Available AWS profile
    * AWS Cli
      * aws-vault binary
  * Azure
    * Available Service account with access and permissions
    * Azure Cli
  * Google Cloud
    * Available Service account with access and permissions
    * gcloud Cli
  * Terragrunt Binary
  * OpenTofu Binary
## How to use this repository
You can use this repository as a template to create your own terraform project. <br/>
Generate your repository through the template through the github interface. <br/>
Clone the repository to your local machine. <br/>
Create a new branch to work on your project. <br/>
This project is configured to support different cloud providers, but one at a time. <br/>
* AWS
* Azure
* Google Cloud

### Initializing the project
You should initialize the project through the makefile command below. <br/>
This command will ask you a series of questions to configure the project. <br/>
```shell
make init/project
```
After successful run of this command, you will have basic configuration of the project available. <br/>
Also your inputs will be saved in 2 files `.inputs` and `.inputs_mod` <br/>
`.inputs` file will have the basic inputs you provided. <br/>
`.inputs_mod` file will have the module inputs for the project you provided. <br/>

## Terragrunt operations
### Plan output
```shell
terragrunt --terragrunt-non-interactive --terragrunt-working-dir <module-path> plan
```

### Plan apply
```shell
terragrunt --terragrunt-non-interactive --terragrunt-working-dir <module-path> apply tfplan.out
```

