namespace PalabratorFs.Handlers

open Microsoft.AspNetCore.Http
open FSharp.Control.Tasks
open Giraffe
open Saturn.Auth

open MongoDB.Bson
open PalabratorFs
open PalabratorFs.Database
open System
open System.Security.Claims
open Saturn.Controller

[<RequireQualifiedAccess>]
module Auth =
    let Login =
        fun (next: HttpFunc) (ctx: HttpContext) ->
            task {
                let! payload = Helpers.TryBindJsonAsync<LoginPayload>(ctx)

                match payload with
                | None ->
                    return!
                        (setStatusCode 400
                         >=> json {| message = "Missing Login Info" |})
                            next
                            ctx
                | Some payload ->
                    let! canLogin = Users.VerifyPassword payload.email payload.password

                    if not canLogin then
                        return!
                            (setStatusCode 401
                             >=> json {| message = "Invalid Credentials" |})
                                next
                                ctx
                    else
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
                let! payload = Helpers.TryBindJsonAsync<SignupPayload>(ctx)

                match payload with
                | None ->
                    return!
                        (setStatusCode 400
                         >=> json {| message = "Missing Signup Info" |})
                            next
                            ctx
                | Some payload ->
                    let! exists = Users.Exists payload.email

                    if exists then
                        return!
                            (setStatusCode 400
                             >=> json {| message = "That email already exists" |})
                                next
                                ctx
                    else
                        let! created = Users.Create payload

                        if created then
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
                        else
                            return!
                                (setStatusCode 422
                                 >=> json {| message = "The email is available but we could not create the user" |})
                                    next
                                    ctx

            }


[<RequireQualifiedAccess>]
module Profiles =

    let ProfilesList =
        fun (next: HttpFunc) (ctx: HttpContext) ->
            task {
                let! user = Helpers.TryExtractUserFromRequest ctx

                match user with
                | None ->
                    return!
                        (setStatusCode 403
                         >=> json {| message = "You don't have access to this resource" |})
                            next
                            ctx
                | Some user ->
                    let (page, limit) = Helpers.ExtractPagination ctx
                    let! results = Profiles.Find user._id (Some page) (Some limit)

                    return! json results next ctx
            }

    let Add =
        fun (next: HttpFunc) (ctx: HttpContext) ->
            task {
                let! user = Helpers.TryExtractUserFromRequest ctx

                match user with
                | None ->
                    return!
                        (setStatusCode 403
                         >=> json {| message = "You don't have access to this resource" |})
                            next
                            ctx
                | Some user ->
                    let! payload = Helpers.TryBindJsonAsync<ProfilePayload> ctx

                    match payload with
                    | None ->
                        return!
                            (setStatusCode 400
                             >=> json {| message = "Missing Profile Information" |})
                                next
                                ctx
                    | Some payload ->
                        match! Profiles.Exists user._id payload.name with
                        | true ->
                            return!
                                (setStatusCode 400
                                 >=> json {| message = "That profile already exists" |})
                                    next
                                    ctx
                        | false ->
                            let! result = Profiles.Create payload

                            if result then
                                let! profiles = Profiles.Find user._id None None
                                return! (setStatusCode 201 >=> json profiles) next ctx
                            else
                                return!
                                    (setStatusCode 422
                                     >=> json {| message = "The profile name is available but we couldn't create it" |})
                                        next
                                        ctx
            }

    let Update =
        fun (next: HttpFunc) (ctx: HttpContext) ->
            task {
                let! user = Helpers.TryExtractUserFromRequest ctx

                match user with
                | None ->
                    return!
                        (setStatusCode 403
                         >=> json {| message = "You don't have access to this resource" |})
                            next
                            ctx
                | Some user ->
                    match! Helpers.TryBindJsonAsync<Profile> ctx with
                    | None ->
                        return!
                            (setStatusCode 400
                             >=> json {| message = "The Profile is not present in the request" |})
                                next
                                ctx
                    | Some payload ->
                        match! Profiles.Exists user._id payload.name with
                        | true ->
                            return!
                                (setStatusCode 400
                                 >=> json {| message = "The Profile name exists already" |})
                                    next
                                    ctx
                        | false ->
                            match! Profiles.Rename payload._id payload.name with
                            | false ->
                                return!
                                    (setStatusCode 422
                                     >=> json {| message = "We were not able to rename the profile" |})
                                        next
                                        ctx
                            | true -> return! json payload next ctx
            }

    let Delete =
        fun (next: HttpFunc) (ctx: HttpContext) ->
            task {
                match! Helpers.TryExtractUserFromRequest ctx with
                | None ->
                    return!
                        (setStatusCode 403
                         >=> json {| message = "You don't have access to this resource" |})
                            next
                            ctx
                | Some user ->
                    match! Helpers.TryBindJsonAsync<Profile> ctx with
                    | None ->
                        return!
                            (setStatusCode 400
                             >=> json {| message = "The Profile is not present in the request" |})
                                next
                                ctx
                    | Some payload ->
                        match! Profiles.Delete payload._id payload.owner with
                        | false ->
                            return!
                                (setStatusCode 422
                                 >=> json {| message = "We were not able to delete this profile" |})
                                    next
                                    ctx
                        | true -> return! setStatusCode 204 next ctx
            }
