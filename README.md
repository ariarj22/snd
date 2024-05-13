# snd

## Table of Contents

- [About](#about)
- [Installation](#installation)
- [Usage](#usage)

## About <a name = "about"></a>

A simple API made using Go, and combining both SQL and NoSQL database.

Created based on [this repository](https://github.com/kubuskotak/king).

## Installation <a name = "installation"></a>

### Prerequisites

- Go 1.19+
- PostgreSQL and MongoDB Server
- Docker (Developed with version 20.+)
- [Taskfile](https://taskfile.dev/) Task runner or Build tool.
- [golangci](https://golangci-lint.run/usage/install/) golang linter.
- [entgo](https://entgo.io/) ORM adapter with sql engine, mysql, postgresql and sqlite.
- For Changelog using [git-chglog](https://github.com/git-chglog/git-chglog)

### Installing

1. Create .env file based on [.env.defaultexample](https://github.com/ariarj22/snd/blob/main/.env.defaultexample)
2. Create PostgreSQL and MongoDB server according to the information in .env file
3. Run PostgreSQL and MongoDB server
4. Run the application

```
task dev
```

## Usage <a name = "usage"></a>

The API has several endpoints to handle specific tasks or data requests within the application:

### User Endpoint

- GET /users, display all users.
- POST /register, register a user.
- POST /login, login a user.
- POST /logout, logout a logged in user.
- GET /:id, display a user based on id.
- DELETE /:id, delete a user based on id.

### Application Endpoint

- GET /apps, display all applications.
- POST /apps, create new application.
- GET /apps/:id, display an application based on id.
- PUT /apps/:id, edit an application based on id.
- DELETE /apps/:id, delete an application based on id.

### Index Endpoint

- GET /apps/indexes, display all indexes from an application.
- POST /apps/indexes, create new index.
- GET /apps/indexes/:id, display an index based on id.
- PUT /apps/indexes/:id, edit an index based on id.
- DELETE /apps/indexes/:id, delete an index based on id.

### Document Endpoint

- GET /apps/indexes/document, display all documents from an index.
- POST /apps/indexes/document, create new document.
- PUT /apps/indexes/document/:id, edit a document based on id.
- DELETE /apps/indexes/document/:id, delete a document based on id.
