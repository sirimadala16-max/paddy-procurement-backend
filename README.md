# Paddy Procurement Management System

A Salesforce-integrated web application for managing farmers, paddy procurement records, weight deductions, bag calculations, payments, reports, and dashboards.

## Project Overview

The Paddy Procurement Management System digitizes the paddy procurement process by connecting a web-based frontend with Salesforce CRM.

The system allows users to:

- Manage farmer records
- Record paddy procurement transactions
- Calculate weighbridge and bag deductions
- Calculate net weight and final bags
- Calculate total procurement amount
- View procurement reports
- Monitor procurement metrics through a Salesforce dashboard
- Generate procurement receipts
- Access Salesforce data through secure REST APIs

## System Architecture

```text
                    User
                      |
                      v
          HTML / CSS / JavaScript
              GitHub Pages
                      |
                      | REST API
                      v
             Node.js + Express
                      |
                      v
                  JSforce
                      |
              OAuth 2.0 + PKCE
                      |
                      v
                Salesforce CRM
                /           \
               /             \
        Farmer__c       Paddy_Procurement__c
                              |
                    Reports & Dashboard
