namespace PalabratorFs

open System
open System.Text.Json
open System.Text.Json.Serialization
open System.Threading.Tasks
open FSharp.Control.Tasks

open Microsoft.AspNetCore.Http

open Giraffe
open Giraffe.Serialization
open MongoDB.Bson
open System.Security.Claims

[<RequireQualifiedAccess>]
module Helpers =
    type ObjectIdConverter() =
        inherit JsonConverter<ObjectId>()

        override _.Read(reader: byref<Utf8JsonReader>, typeToConvert: Type, options: JsonSerializerOptions) =
            ObjectId.Parse(reader.GetString())

        override _.Write(writer: Utf8JsonWriter, value: ObjectId, options: JsonSerializerOptions) =
            writer.WriteStringValue(value.ToString())


    let TryExtractUserFromRequest (ctx: HttpContext) =
        task {
            let emailClaim =
                ctx.User.FindFirst(fun claim -> claim.Type = ClaimTypes.Email)
                |> Option.ofObj

            match emailClaim with
            | None -> return None
            | Some claim -> return! Database.Users.FindByEmail(claim.Value)
        }


    let ExtractPagination (ctx: HttpContext) =
        let page =
            ctx.TryGetQueryStringValue "page"
            |> Option.map
                (fun value ->
                    match System.Int32.TryParse value with
                    | true, value -> value
                    | false, _ -> 1)
            |> Option.defaultValue 1

        let limit =
            ctx.TryGetQueryStringValue "limit"
            |> Option.map
                (fun value ->
                    match System.Int32.TryParse value with
                    | true, value -> value
                    | false, _ -> 20)
            |> Option.defaultValue 20

        (page, limit)

    let TryBindJsonAsync<'T> (ctx: HttpContext) =
        task {
            try
                let! payload = ctx.BindJsonAsync<'T>()
                return Some payload
            with ex -> return None
        }


    let JwtSecret =
        System.Environment.GetEnvironmentVariable("PALABRATOR_JWT_SECRET")
        |> Option.ofObj
        |> Option.defaultValue "wow much secret :9"

    let JsonSerializer =
        let opts = JsonSerializerOptions()
        opts.AllowTrailingCommas <- true
        opts.ReadCommentHandling <- JsonCommentHandling.Skip
        opts.IgnoreNullValues <- true
        opts.Converters.Add(JsonFSharpConverter())
        opts.Converters.Add(ObjectIdConverter())
        { new IJsonSerializer with
            member __.Deserialize<'T>(arg1: byte []): 'T =
                let spn = ReadOnlySpan(arg1)
                JsonSerializer.Deserialize<'T>(spn, opts)

            member __.Deserialize<'T>(arg1: string): 'T =
                JsonSerializer.Deserialize<'T>(arg1, opts)

            member __.DeserializeAsync(arg1: IO.Stream): Task<'T> =
                JsonSerializer
                    .DeserializeAsync<'T>(arg1, opts)
                    .AsTask()

            member __.SerializeToBytes<'T>(arg1: 'T): byte array =
                JsonSerializer.SerializeToUtf8Bytes(arg1, opts)

            member __.SerializeToStreamAsync<'T> (arg1: 'T) (arg2: IO.Stream): Task =
                JsonSerializer.SerializeAsync(arg2, arg1, opts)

            member __.SerializeToString<'T>(arg1: 'T): string =
                JsonSerializer.Serialize(arg1, typeof<'T>, opts) }
