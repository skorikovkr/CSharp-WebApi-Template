namespace WebApiTemplate.POCO
{
    public class TokenPair
    {
        public required string AccessToken { get; set; }
        public required string RefreshToken { get; set; }
        public required DateTime RefreshTokenValidTo { get; set; }
    }
}
