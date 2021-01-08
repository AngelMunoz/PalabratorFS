namespace PalabratorFs

open MongoDB.Bson

[<CLIMutable>]
type LoginPayload = { email: string; password: string }

[<CLIMutable>]
type SignupPayload =
    { name: string
      email: string
      password: string }

type UserPayload =
    { _id: ObjectId
      name: string
      email: string
      password: string }

type User =
    { _id: ObjectId
      name: string
      email: string }

type Profile =
    { _id: ObjectId
      owner: ObjectId
      name: string }

type ProfilePayload = { owner: ObjectId; name: string }
type PaginatedResult<'T> = { list: seq<'T>; count: int }
