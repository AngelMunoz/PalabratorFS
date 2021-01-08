namespace PalabratorFs.Handlers

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

    let unprocessableEntity (msg: string) =
        RequestErrors.UNPROCESSABLE_ENTITY { message = msg }

[<RequireQualifiedAccess>]
module Auth =
    let Login =
        fun (next: HttpFunc) (ctx: HttpContext) ->
            task {
                match! Helpers.TryBindJsonAsync<LoginPayload> ctx with
                | None -> return! badRequest "Missing Login Info" next ctx
                | Some payload ->
                    match! Users.VerifyPassword payload.email payload.password with
                    | false -> return! unauthorized "Invalid Credentials" next ctx
                    | true ->
                        let claims =
                            [ Claim(ClaimTypes.Email, payload.email) ]

                        let token =
                            generateJWT
                                (Helpers.JwtSecret, "HS256")
                                "http://localhost:5000"
                                (DateTime.Now.AddDays(1.0))
                                claims

                        return!
                            json
                                {| email = payload.email
                                   token = token |}
                                next
                                ctx
            }

    let Signup =
        fun (next: HttpFunc) (ctx: HttpContext) ->
            task {
                match! Helpers.TryBindJsonAsync<SignupPayload> ctx with
                | None -> return! badRequest "Missing Signup Info" next ctx
                | Some payload ->
                    match! Users.Exists payload.email with
                    | true -> return! badRequest "That email already exists" next ctx
                    | false ->
                        match! Users.Create payload with
                        | false ->
                            return!
                                unprocessableEntity "The email is available but we could not create the user" next ctx
                        | true ->
                            let claims =
                                [ Claim(ClaimTypes.Email, payload.email) ]

                            let token =
                                generateJWT
                                    (Helpers.JwtSecret, "HS256")
                                    "http://localhost:5000"
                                    (DateTime.Now.AddDays(1.0))
                                    claims

                            return!
                                created
                                    {| email = payload.email
                                       token = token |}
                                    next
                                    ctx
            }


[<RequireQualifiedAccess>]
module Profiles =

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
            task {
                match! Helpers.TryExtractUserFromRequest ctx with
                | None -> return! forbidden "You don't have access to this resource" next ctx
                | Some user ->
                    match! Helpers.TryBindJsonAsync<ProfilePayload> ctx with
                    | None -> return! badRequest "Missing Profile Information" next ctx
                    | Some payload ->
                        match! Profiles.Exists user._id payload.name with
                        | true -> return! badRequest "That profile already exists" next ctx
                        | false ->
                            match! Profiles.Create payload with
                            | false ->
                                return!
                                    unprocessableEntity
                                        "The profile name is available but we couldn't create it"
                                        next
                                        ctx
                            | true ->
                                let (page, limit) = Helpers.ExtractPagination ctx
                                let! profiles = Profiles.Find user._id (Some page) (Some limit)
                                return! created profiles next ctx
            }

    let Update =
        fun (next: HttpFunc) (ctx: HttpContext) ->
            task {
                match! Helpers.TryExtractUserFromRequest ctx with
                | None -> return! forbidden "You don't have access to this resource" next ctx
                | Some user ->
                    match! Helpers.TryBindJsonAsync<Profile> ctx with
                    | None -> return! badRequest "The Profile is not present in the request" next ctx
                    | Some payload ->
                        if payload.owner <> user._id then
                            return! forbidden "You don't have access to this resource" next ctx
                        else
                            match! Profiles.Exists user._id payload.name with
                            | true -> return! badRequest "The Profile name exists already" next ctx
                            | false ->
                                match! Profiles.Rename payload._id payload.name with
                                | false -> return! unprocessableEntity "We were not able to rename the profile" next ctx
                                | true -> return! json payload next ctx
            }

    let Delete =
        fun (next: HttpFunc) (ctx: HttpContext) ->
            task {
                match! Helpers.TryExtractUserFromRequest ctx with
                | None -> return! forbidden "You don't have access to this resource" next ctx
                | Some user ->
                    match! Helpers.TryBindJsonAsync<Profile> ctx with
                    | None -> return! badRequest "The Profile is not present in the request" next ctx
                    | Some payload ->
                        if payload.owner <> user._id then
                            return! forbidden "You don't have access to this resource" next ctx
                        else
                            match! Profiles.Delete payload._id payload.owner with
                            | false -> return! unprocessableEntity "We were not able to delete this profile" next ctx
                            | true -> return! setStatusCode 204 next ctx
            }
