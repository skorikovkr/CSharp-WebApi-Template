namespace WebApiTemplate.POCO
{
    public class TokenPair
    {
        public required string AccessToken { get; set; }
        public required string RefreshToken { get; set; }
        public DateTime? RefreshTokenValidTo { get; set; }
        public DateTime? AccessTokenValidTo { get; set; }
    }
}
