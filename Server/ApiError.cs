namespace RouterNftConfig.Server;

public class ApiError {
    public const string AppNonConfigured =nameof(AppNonConfigured);
    public const string NotAuthenticated = nameof(NotAuthenticated);
    public const string NotAuthorized = nameof(NotAuthorized);
    public const string NotFound = nameof(NotFound);
    public const string ValidationError = nameof(ValidationError);

    public const string ValueMandatory = nameof(ValueMandatory);
    public const string ValueInvalidFormat = nameof(ValueInvalidFormat);
    public const string ValueNotUnique = nameof(ValueNotUnique);
    public const string ValueDuplicate = nameof(ValueDuplicate);
    public const string ValueMustBeNull = nameof(ValueMustBeNull);

    public ApiError() {
        Code = string.Empty;
    }

    public ApiError(string code, string? description=null) {
        Code = code;
        Description = description;
    }

    public ApiError WithPropertyError(string property, string error) {
        property = char.ToLower(property[0]) + property.Substring(1);
        PropertyErrors ??= new Dictionary<string, string[]>();
        if (PropertyErrors.TryGetValue(property, out var x))
            PropertyErrors[property] = x.Append(error).Distinct().ToArray();
        else PropertyErrors[property] = new[] { error };
        return this;
    }

    public ApiError WithOffendingId(int id) {
        if (OffendingIds == null)
            OffendingIds = new[] { id };
        else
            OffendingIds = OffendingIds.Append(id).ToArray();
        return this;
    }
    public string Code { get; set; }
    public string? Description { get; set; }
    public int[]? OffendingIds { get; set; }
    public Dictionary<string, string[]>? PropertyErrors { get; set; } = null;
}
