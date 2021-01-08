namespace PalabratorFs

open Microsoft.AspNetCore.Http

open FSharp.Control.Tasks

open Giraffe

open Saturn.Application
open Saturn.Pipeline
open Saturn.CSRF
open Saturn.Endpoint


open PalabratorFs.Handlers
open Microsoft.IdentityModel.Tokens

module Program =

    let apiPipeline =
        pipeline { set_header "x-app-name" "palabrator" }

    let protectedApi =
        pipeline { requires_authentication (ResponseWriters.json {| message = "Failed to authenticate" |}) }

    let api =
        router {
            pipe_through protectedApi
            get "/profiles" Profiles.ProfilesList
            post "/profiles" Profiles.Add
            put "/profiles" Profiles.Update
            delete "/profiles" Profiles.Delete
        }

    let approuter =
        router {
            pipe_through apiPipeline
            post "/auth/login" Auth.Login
            post "/auth/signup" Auth.Signup
            forward "/api" api
        }

    let app =

        application {
            use_json_serializer Helpers.JsonSerializer
            use_endpoint_router approuter
            use_jwt_authentication Helpers.JwtSecret "http://localhost:5000"
            use_gzip
        }

    [<EntryPoint>]
    let main _ =
        run app
        0 // return an integer exit code
