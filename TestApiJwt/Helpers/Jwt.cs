namespace TestApiJwt.Helpers
{
    public class Jwt
    {
        public string key { get; set; }
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public double Duration { get; set; }
    }
}
