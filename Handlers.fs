namespace PalabratorFs.Handlers

open FsToolkit.ErrorHandling
open FsToolkit.ErrorHandling.Operator.TaskResult
open Microsoft.AspNetCore.Authentication.JwtBearer
open Microsoft.AspNetCore.Http
open FSharp.Control.Tasks
open Giraffe
open Saturn.Auth

open PalabratorFs
open PalabratorFs.Database
open System
open System.Security.Claims

[<AutoOpen>]
module private Responses =
    type Response = { message: string }
    let created<'T> (value: 'T) = Successful.CREATED value

    let badRequest (msg: string) =
        RequestErrors.BAD_REQUEST { message = msg }

    let unauthorized (msg: string) =
        RequestErrors.UNAUTHORIZED JwtBearerDefaults.AuthenticationScheme "http://localhost:5001" { message = msg }

    let forbidden (msg: string) =
        RequestErrors.FORBIDDEN { message = msg }

    let serverError (msg: string) =
        ServerErrors.INTERNAL_ERROR { message = msg }

[<RequireQualifiedAccess>]
module Auth =
    type AuthErrors =
        | BadRequest of string
        | Unauthorized of string
        | ServerError of string

    let Login =
        fun (next: HttpFunc) (ctx: HttpContext) ->
            taskResult {
                let! payload =
                    Helpers.TryBindJsonAsync<LoginPayload> ctx
                    |> TaskResult.requireSome (BadRequest "Missing Login Info")

                do! Users.VerifyPassword payload.email payload.password
                    |> TaskResult.requireTrue (Unauthorized "Invalid Credentials")

                let claims =
                    [ Claim(ClaimTypes.Email, payload.email) ]

                let token =
                    generateJWT (Helpers.JwtSecret, "HS256") "http://localhost:5000" (DateTime.Now.AddDays(1.0)) claims

                return
                    {| email = payload.email
                       token = token |}
            }
            |> fun result ->
                task {
                    match! result with
                    | Ok result -> return! json result next ctx
                    | Error (BadRequest error) -> return! badRequest error next ctx
                    | Error (Unauthorized error) -> return! unauthorized error next ctx
                    | Error (ServerError error) -> return! serverError error next ctx
                }

    let Signup =
        fun (next: HttpFunc) (ctx: HttpContext) ->
            taskResult {
                let! payload =
                    Helpers.TryBindJsonAsync<SignupPayload> ctx
                    |> TaskResult.requireSome (BadRequest "Missing Signup Info")

                do! Users.Exists payload.email
                    |> TaskResult.requireFalse (BadRequest "That email already exists")

                do! Users.Create payload
                    |> TaskResult.requireTrue (ServerError "The email is available but we could not create the user")

                let claims =
                    [ Claim(ClaimTypes.Email, payload.email) ]

                let token =
                    generateJWT (Helpers.JwtSecret, "HS256") "http://localhost:5000" (DateTime.Now.AddDays(1.0)) claims

                return
                    {| email = payload.email
                       token = token |}
            }
            |> fun result ->
                task {
                    match! result with
                    | Ok result -> return! created result next ctx
                    | Error (BadRequest error) -> return! badRequest error next ctx
                    | Error (ServerError error) -> return! serverError error next ctx
                    | Error (Unauthorized error) -> return! unauthorized error next ctx
                }


[<RequireQualifiedAccess>]
module Profiles =
    type ProfileErrors =
        | Forbidden of string
        | BadRequest of string
        | ServerError of string

    let ProfilesList =
        fun (next: HttpFunc) (ctx: HttpContext) ->
            task {
                match! Helpers.TryExtractUserFromRequest ctx with
                | None -> return! forbidden "You don't have access to this resource" next ctx
                | Some user ->
                    let (page, limit) = Helpers.ExtractPagination ctx
                    let! results = Profiles.Find user._id (Some page) (Some limit)

                    return! json results next ctx
            }


    let Add =
        fun (next: HttpFunc) (ctx: HttpContext) ->
            taskResult {
                let! user =
                    Helpers.TryExtractUserFromRequest ctx
                    |> TaskResult.requireSome (Forbidden "You don't have access to this resource")

                let! payload =
                    Helpers.TryBindJsonAsync<ProfilePayload> ctx
                    |> TaskResult.requireSome (BadRequest "Missing Profile Information")

                do! Profiles.Exists user._id payload.name
                    |> TaskResult.requireFalse (BadRequest "That profile already exists")

                do! Profiles.Create payload
                    |> TaskResult.requireTrue (ServerError "The profile name is available but we couldn't create it")

                let (page, limit) = Helpers.ExtractPagination ctx
                return! Profiles.Find user._id (Some page) (Some limit)
            }
            |> fun result ->
                task {
                    match! result with
                    | Ok result -> return! created result next ctx
                    | Error (Forbidden error) -> return! forbidden error next ctx
                    | Error (BadRequest error) -> return! badRequest error next ctx
                    | Error (ServerError error) -> return! badRequest error next ctx
                }

    let Update =
        fun (next: HttpFunc) (ctx: HttpContext) ->
            taskResult {
                let! user =
                    Helpers.TryExtractUserFromRequest ctx
                    |> TaskResult.requireSome (Forbidden "You don't have access to this resource")

                let! payload =
                    Helpers.TryBindJsonAsync<Profile> ctx
                    |> TaskResult.requireSome (BadRequest "The Profile is not present in the request")

                do! payload.owner <> user._id
                    |> Result.requireFalse (Forbidden "You don't have access to this resource")

                do! Profiles.Exists user._id payload.name
                    |> TaskResult.requireFalse (BadRequest "The Profile name exists already")

                do! Profiles.Rename payload._id payload.name
                    |> TaskResult.requireTrue (ServerError "We were not able to rename the profile")

                return payload
            }
            |> fun result ->
                task {
                    match! result with
                    | Ok result -> return! json result next ctx
                    | Error (Forbidden error) -> return! forbidden error next ctx
                    | Error (BadRequest error) -> return! badRequest error next ctx
                    | Error (ServerError error) -> return! badRequest error next ctx
                }

    let Delete =
        fun (next: HttpFunc) (ctx: HttpContext) ->
            taskResult {
                let! user =
                    Helpers.TryExtractUserFromRequest ctx
                    |> TaskResult.requireSome (Forbidden "You don't have access to this resource")

                let! payload =
                    Helpers.TryBindJsonAsync<Profile> ctx
                    |> TaskResult.requireSome (BadRequest "The Profile is not present in the request")

                do! payload.owner <> user._id
                    |> Result.requireFalse (Forbidden "You don't have access to this resource")

                do! Profiles.Delete payload._id payload.owner
                    |> TaskResult.requireTrue (ServerError "You don't have access to this resource")

                return ()
            }
            |> fun result ->
                task {
                    match! result with
                    | Ok () -> return! setStatusCode 204 next ctx
                    | Error (Forbidden error) -> return! forbidden error next ctx
                    | Error (BadRequest error) -> return! badRequest error next ctx
                    | Error (ServerError error) -> return! badRequest error next ctx
                }
