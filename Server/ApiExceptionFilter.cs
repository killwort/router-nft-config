using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using RouterNftConfig.Server;

namespace RouterNftConfig.Server;

public class ApiExceptionFilter : IActionFilter, IOrderedFilter {
    public int Order => int.MaxValue - 10;

    public void OnActionExecuting(ActionExecutingContext context) { }

    public void OnActionExecuted(ActionExecutedContext context) {
        if (context.Exception is ApiErrorException apiErrorException) {
            context.Result = new JsonResult(
                new ApiResponse {
                    Success = false,
                    Error = apiErrorException.Error
                }
            ) { StatusCode = 400 };

            context.ExceptionHandled = true;
        }
    }
}
