using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Blockchain
{
	public class CryptoHelper
	{
		public static string ToSHA256(object data)
		{
			StringBuilder sb = new StringBuilder();
			SHA256 mySHA256 = SHA256Managed.Create();
			if (data as byte[] != null)
			{
				foreach (Byte b in data as byte[])
					sb.Append(b.ToString("x2"));
				return sb.ToString();
			}

			BinaryFormatter bf = new BinaryFormatter();
			using (MemoryStream ms = new MemoryStream())
			{
				bf.Serialize(ms, data);
				byte[] hashBytes = mySHA256.ComputeHash(ms.ToArray());

				foreach (Byte b in hashBytes)
					sb.Append(b.ToString("x2"));

				return sb.ToString();
			}
		}

		public static byte[] ToSHA256Bytes(object data)
		{
			SHA256 mySHA256 = SHA256Managed.Create();
			if (data as byte[] != null)
			{
				return mySHA256.ComputeHash(data as byte[]);
			}
			BinaryFormatter bf = new BinaryFormatter();
			using (MemoryStream ms = new MemoryStream())
			{
				bf.Serialize(ms, data);
				return mySHA256.ComputeHash(ms.ToArray());
			}
		}


		public static byte[] HashAndSignBytes(byte[] DataToSign, RSAParameters Key)
		{
			try
			{
				// Create a new instance of RSACryptoServiceProvider using the 
				// key from RSAParameters.  
				RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();

				RSAalg.ImportParameters(Key);

				// Hash and sign the data. Pass a new instance of SHA1CryptoServiceProvider
				// to specify the use of SHA1 for hashing.
				return RSAalg.SignData(DataToSign, new SHA256CryptoServiceProvider());
			}
			catch (CryptographicException e)
			{
				Console.WriteLine(e.Message);

				return null;
			}
		}

		public static byte[] StringToByteArray(String hex)
		{
			int NumberChars = hex.Length;
			byte[] bytes = new byte[NumberChars / 2];
			for (int i = 0; i < NumberChars; i += 2)
				bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
			return bytes;
		}

		public static bool VerifySignedHash(byte[] DataToVerify, byte[] SignedData, RSAParameters Key)
		{

			string toPem = CryptoHelper.PublicPEM(Key);
			try
			{
				// Create a new instance of RSACryptoServiceProvider using the 
				// key from RSAParameters.
				RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();
				RSAalg.ImportParameters(Key);

				byte[] hashed = CryptoHelper.ToSHA256Bytes(DataToVerify);

				string hexStrSign = Encoding.UTF8.GetString(SignedData);
				byte[] sign2 = SignedData;// StringToByteArray(hexStrSign);

				string byteToHex = BitConverter.ToString(sign2).Replace("-", string.Empty).ToLower();

				bool t3 = RSAalg.VerifyData(DataToVerify, new SHA256CryptoServiceProvider(), sign2);
				bool t5 = RSAalg.VerifyHash(hashed, CryptoConfig.MapNameToOID("SHA256"), sign2);

				bool verified = t3 && t5;

				// Verify the data using the signature.  Pass a new instance of SHA1CryptoServiceProvider
				// to specify the use of SHA1 for hashing.
				return verified;

			}
			catch (CryptographicException e)
			{
				Console.WriteLine(e.Message);

				return false;
			}
		}

		public static BigInteger FromBigEndian(byte[] p)
		{
			Array.Reverse(p);
			if (p[p.Length - 1] > 127)
			{
				Array.Resize(ref p, p.Length + 1);
				p[p.Length - 1] = 0;
			}
			return new BigInteger(p);
		}

		public static string PrivatePEM(RSAParameters parameters)
		{
			using (var stream = new MemoryStream())
			{
				var writer = new BinaryWriter(stream);
				writer.Write((byte)0x30); // SEQUENCE
				using (var innerStream = new MemoryStream())
				{
					var innerWriter = new BinaryWriter(innerStream);
					EncodeIntegerBigEndian(innerWriter, new byte[] { 0x00 }); // Version
					EncodeIntegerBigEndian(innerWriter, parameters.Modulus);
					EncodeIntegerBigEndian(innerWriter, parameters.Exponent);
					EncodeIntegerBigEndian(innerWriter, parameters.D);
					EncodeIntegerBigEndian(innerWriter, parameters.P);
					EncodeIntegerBigEndian(innerWriter, parameters.Q);
					EncodeIntegerBigEndian(innerWriter, parameters.DP);
					EncodeIntegerBigEndian(innerWriter, parameters.DQ);
					EncodeIntegerBigEndian(innerWriter, parameters.InverseQ);
					var length = (int)innerStream.Length;
					EncodeLength(writer, length);
					writer.Write(innerStream.GetBuffer(), 0, length);
				}

				string base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length);
				StringBuilder sb = new StringBuilder();
				sb.AppendLine("-----BEGIN RSA PRIVATE KEY-----");
				// Output as Base64 with lines chopped at 64 characters
				for (var i = 0; i < base64.Length; i += 64)
				{
					sb.AppendLine(base64.Substring(i, Math.Min(64, base64.Length - i)));
					//outputStream.WriteLine(base64, i, Math.Min(64, base64.Length - i));
				}
				sb.AppendLine("-----END RSA PRIVATE KEY-----");

				return sb.ToString().Replace("\\", "\\\\");
			}
		}

		public static RSAParameters ReadPEM(string pemstr)
		{
			StringReader sr = new StringReader(pemstr);
			PemReader pr = new PemReader(sr);

			var KeyParameter = (Org.BouncyCastle.Crypto.AsymmetricKeyParameter)pr.ReadObject();
			return DotNetUtilities.ToRSAParameters((RsaKeyParameters)KeyParameter);
		}

		public static string PublicPEM(RSAParameters parameters)
		{
			using (var stream = new MemoryStream())
			{
				var writer = new BinaryWriter(stream);
				writer.Write((byte)0x30); // SEQUENCE
				using (var innerStream = new MemoryStream())
				{
					var innerWriter = new BinaryWriter(innerStream);
					innerWriter.Write((byte)0x30); // SEQUENCE
					EncodeLength(innerWriter, 13);
					innerWriter.Write((byte)0x06); // OBJECT IDENTIFIER
					var rsaEncryptionOid = new byte[] { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
					EncodeLength(innerWriter, rsaEncryptionOid.Length);
					innerWriter.Write(rsaEncryptionOid);
					innerWriter.Write((byte)0x05); // NULL
					EncodeLength(innerWriter, 0);
					innerWriter.Write((byte)0x03); // BIT STRING
					using (var bitStringStream = new MemoryStream())
					{
						var bitStringWriter = new BinaryWriter(bitStringStream);
						bitStringWriter.Write((byte)0x00); // # of unused bits
						bitStringWriter.Write((byte)0x30); // SEQUENCE
						using (var paramsStream = new MemoryStream())
						{
							var paramsWriter = new BinaryWriter(paramsStream);
							EncodeIntegerBigEndian(paramsWriter, parameters.Modulus); // Modulus
							EncodeIntegerBigEndian(paramsWriter, parameters.Exponent); // Exponent
							var paramsLength = (int)paramsStream.Length;
							EncodeLength(bitStringWriter, paramsLength);
							bitStringWriter.Write(paramsStream.GetBuffer(), 0, paramsLength);
						}
						var bitStringLength = (int)bitStringStream.Length;
						EncodeLength(innerWriter, bitStringLength);
						innerWriter.Write(bitStringStream.GetBuffer(), 0, bitStringLength);
					}
					var length = (int)innerStream.Length;
					EncodeLength(writer, length);
					writer.Write(innerStream.GetBuffer(), 0, length);
				}

				string base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length);
				StringBuilder sb = new StringBuilder();
				sb.AppendLine("-----BEGIN PUBLIC KEY-----");
				// Output as Base64 with lines chopped at 64 characters
				for (var i = 0; i < base64.Length; i += 64)
				{
					sb.AppendLine(base64.Substring(i, Math.Min(64, base64.Length - i)));
					//outputStream.WriteLine(base64, i, Math.Min(64, base64.Length - i));
				}
				sb.AppendLine("-----END PUBLIC KEY-----");

				return sb.ToString();
			}
		}

		private static void EncodeLength(BinaryWriter stream, int length)
		{
			if (length < 0) throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
			if (length < 0x80)
			{
				// Short form
				stream.Write((byte)length);
			}
			else
			{
				// Long form
				var temp = length;
				var bytesRequired = 0;
				while (temp > 0)
				{
					temp >>= 8;
					bytesRequired++;
				}
				stream.Write((byte)(bytesRequired | 0x80));
				for (var i = bytesRequired - 1; i >= 0; i--)
				{
					stream.Write((byte)(length >> (8 * i) & 0xff));
				}
			}
		}

		private static void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned = true)
		{
			stream.Write((byte)0x02); // INTEGER
			var prefixZeros = 0;
			for (var i = 0; i < value.Length; i++)
			{
				if (value[i] != 0) break;
				prefixZeros++;
			}
			if (value.Length - prefixZeros == 0)
			{
				EncodeLength(stream, 1);
				stream.Write((byte)0);
			}
			else
			{
				if (forceUnsigned && value[prefixZeros] > 0x7f)
				{
					// Add a prefix zero to force unsigned if the MSB is 1
					EncodeLength(stream, value.Length - prefixZeros + 1);
					stream.Write((byte)0);
				}
				else
				{
					EncodeLength(stream, value.Length - prefixZeros);
				}
				for (var i = prefixZeros; i < value.Length; i++)
				{
					stream.Write(value[i]);
				}
			}

		}
	}
}