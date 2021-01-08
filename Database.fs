namespace PalabratorFs

open System
open System.Threading.Tasks

open FSharp.Control.Tasks

open MongoDB.Bson
open MongoDB.Driver

open Mondocks.Queries
open Mondocks.Aggregation
open Mondocks.Types

open BCrypt.Net


module Database =

    let private dburl =
        Environment.GetEnvironmentVariable("PALABRATOR_DB_URL")
        |> Option.ofObj
        |> Option.defaultValue "mongodb://localhost:27017/"

    [<Literal>]
    let private DbName = "palabratorfs"

    [<Literal>]
    let private UsersCol = "pal_users"

    [<Literal>]
    let private ProfilesCol = "pal_profiles"

    [<Literal>]
    let private WordsCol = "pal_words"

    let db =
        lazy (MongoClient(dburl).GetDatabase(DbName))


    [<RequireQualifiedAccess>]
    module Users =
        let Create (user: SignupPayload) =
            let user =
                { user with
                      password = BCrypt.EnhancedHashPassword user.password }

            let createCmd = insert UsersCol { documents [ user ] }

            task {
                let! result = db.Value.RunCommandAsync<InsertResult>(JsonCommand createCmd)
                return result.ok = 1.0 && result.n = 1
            }

        let FindById (_id: ObjectId) =
            task {
                let q =
                    find UsersCol {
                        filter {| _id = _id |}
                        projection {| email = 1; name = 1 |}
                    }

                let! result = db.Value.RunCommandAsync<FindResult<User>>(JsonCommand q)

                return (result.cursor.firstBatch |> Seq.tryHead)
            }

        let FindByEmail (email: string) =
            task {
                let q =
                    find UsersCol {
                        filter {| email = email |}
                        projection {| email = 1; name = 1 |}
                    }

                let! result = db.Value.RunCommandAsync<FindResult<User>>(JsonCommand q)

                return (result.cursor.firstBatch |> Seq.tryHead)
            }

        let Exists (email: string) =
            task {
                let q =
                    count {
                        collection UsersCol
                        query {| email = email |}
                    }

                let! result = db.Value.RunCommandAsync<CountResult>(JsonCommand q)
                return result.ok = 1.0 && result.n >= 1
            }

        let VerifyPassword (email: string) (password: string) =
            task {
                let q =
                    find UsersCol {
                        filter {| email = email |}
                        projection {| password = 1 |}
                    }

                let! result = db.Value.RunCommandAsync<FindResult<{| _id: ObjectId; password: string |}>>(JsonCommand q)

                return
                    match result.cursor.firstBatch |> Seq.tryHead with
                    | None -> false
                    | Some found -> BCrypt.EnhancedVerify(password, found.password)
            }


    [<RequireQualifiedAccess>]
    module Profiles =

        let Exists (owner: ObjectId) (name: string) =
            task {
                let countCmd =
                    count {
                        collection ProfilesCol
                        query {| owner = owner; name = name |}
                    }

                let! result = db.Value.RunCommandAsync<CountResult>(JsonCommand countCmd)

                return result.n > 0
            }

        let Find (owner: ObjectId) (page: Option<int>) (limit: Option<int>) =
            task {
                let page = defaultArg page 1
                let amount = defaultArg limit 10
                let criteria = {| owner = owner |}

                let findCmd =
                    let offset = (page - 1) * amount

                    find ProfilesCol {
                        filter criteria
                        skip offset
                        limit amount
                    }

                let countCmd =
                    count {
                        collection ProfilesCol
                        query criteria
                    }

                let! queryResult = db.Value.RunCommandAsync<FindResult<Profile>>(JsonCommand findCmd)
                let! countResult = db.Value.RunCommandAsync<CountResult>(JsonCommand countCmd)

                return
                    { list = queryResult.cursor.firstBatch
                      count = countResult.n }
            }

        let Create (payload: ProfilePayload) =
            task {
                let insertCmd =
                    insert ProfilesCol { documents [ payload ] }

                let! result = db.Value.RunCommandAsync<InsertResult>(JsonCommand insertCmd)
                return result.n > 0 && result.ok = 1.0
            }

        let Rename (id: ObjectId) (name: string) =
            task {
                let renameCmd =
                    update ProfilesCol {
                        updates [
                            box
                                {| q = {| _id = id |}
                                   u = {| ``$set`` = {| name = name |} |}
                                   multi = false
                                   upsert = false |}
                        ]
                    }

                let! result = db.Value.RunCommandAsync<UpdateResult>(JsonCommand renameCmd)
                return result.n > 0 && result.ok = 1.0
            }

        let Delete (id: ObjectId) (owner: ObjectId) =
            task {
                let renameCmd =
                    delete ProfilesCol {
                        deletes [
                            box
                                {| q = {| _id = id; owner = owner |}
                                   limit = 1 |}
                        ]
                    }

                let! result = db.Value.RunCommandAsync<DeleteResult>(JsonCommand renameCmd)
                return result.n > 0 && result.ok = 1.0
            }
