namespace Company.Function
{
    public class EncryptionEnvelope
    {
        public EncryptionEnvelope() {}
        
        public string Key { get; set; }
        public string Data { get; set; }
        public string FileName { get; set; }
    }
}