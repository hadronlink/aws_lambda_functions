# Lambda Functions Repository

This repository contains all AWS Lambda functions for the project.

## Structure
## Deployment

- **Dev Branch** → Deploys to `*_dev` Lambda functions
- **Main Branch** → Deploys to production Lambda functions

## How to Update a Function

1. Make changes to the `.py` file in VSCode
2. Commit and push to `dev` branch for testing
3. Merge to `main` branch for production deployment

## Functions with Dependencies

Functions with external libraries have a `requirements.txt` file:
- quotes / quotes_dev
- invoices / invoices_dev
- services_requests / services_requests_dev

**Note:** Pillow and google-cloud-storage are provided by Lambda layers (not in requirements.txt)
