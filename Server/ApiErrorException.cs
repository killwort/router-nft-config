using System;

namespace RouterNftConfig.Server;

public class ApiErrorException : Exception {
    public ApiError Error { get; }
    public ApiErrorException(ApiError error) { Error = error; }
}