using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Tangle.Net.Entity;
using Tangle.Net.Repository;
using Tangle.Net.Utils;
using System.Security.Cryptography;
using Blockchain;

namespace Entangle
{
	class Node
	{
		public RSAParameters PublicKey;
		public RSAParameters PrivateKey;
		public string Chunk = "";

		public Node()
		{
			RSACryptoServiceProvider RSAalg = new RSACryptoServiceProvider();
			PrivateKey = RSAalg.ExportParameters(true);
			PublicKey = RSAalg.ExportParameters(false);
		}

		public string PublicKeyString
		{
			get
			{
				return Blockchain.CryptoHelper.PublicPEM(PublicKey);
			}
		}
	}

	class Program
	{
		const int CHUNK_SIZE_BYTES = 128;

		static RestIotaRepository repository;

		static byte[] GetHash(string input)
		{
			HashAlgorithm algorithm = SHA256.Create();
			return algorithm.ComputeHash(Encoding.UTF8.GetBytes(input));
		}

		public static string GetHashString(string input)
		{
			StringBuilder sb = new StringBuilder();
			foreach (byte b in GetHash(input))
				sb.Append(b.ToString("X2"));

			return sb.ToString();
		}

		static void Main(string[] args)
		{
			int currentEpoch = 0;
			Node node1 = new Node();
			Node node2 = new Node();
			// We send chunk to a trusted node
			node1.Chunk = "0x1337EncryptedChunk";

			// Nodes propagate data autonomously 
			// Suggestion for incentivized propegation through financial incentive and relief of burden =>
			// 1. Nodes can opt freely to propagate chunks further but do not have to do so
			// 2. Nodes can only propegate data that is of the current epoch, when data is propegated a record is made on the tangle so that 
			// the client can find the new node and to prove transfer was of the current epoch, all illegal propegation can therefor be skipped.
			// the node will go through normal storage pipeline with other nodes and will thus pay for the chunks itself that it may/maynot store itself.
			// accepting a lot of contracts even though you past through can be beneficial for the node because it improves its metrics of storage and reputation
			// client is responsible to periodically verify enough nodes are storing the data
			// The client can derive a new temporal salt with an iterator if rebroadcast must be done in the current epoch temporalSalt = hash(seed + iterator + currentepoch)

			//propegation happens in current epoch
			node2.Chunk = node1.Chunk;

			//Epoch passes
			currentEpoch++;

			//Client wants proof of node1 and any possible neighbours (recursive n depth search with heuristics?)
			//Two nodes are found to hold the data

			//A client generates a sequential deterministic hash we will call TemporalSalt[Seed0,Seed1,SeedN]
			//with the storage handle (decryption key) functioning as a seed 
			//for every node to ask for proof of storage you compute a unique hash from the combined TemporalSalt and Node PublicKey called MixSalt.
			//First get temporal salt for current epoch
			string seed = "myHandle";
			string temporalSalt = GetHashString(seed + currentEpoch);

			string node1MixedSalt = GetHashString(temporalSalt + node1.PublicKeyString);
			string node2MixedSalt = GetHashString(temporalSalt + node2.PublicKeyString);

			//Mixed salts are posted on the iota tangle with the public node address as tag + epoch (later through iota smart contract invocation ?)
			//The node finds a new transcation for this epoch with his public address, the node knows it has to provide proof of storage

			//the node creates hash Proof = hash(chunk + mixedsalt)
			string node1Proof = GetHashString(node1.Chunk + node1MixedSalt);
			string node2Proof = GetHashString(node2.Chunk + node2MixedSalt);

			//Nodes sign proof
			byte[] node1ProofSignature = CryptoHelper.HashAndSignBytes(UTF8Encoding.UTF8.GetBytes(node1Proof), node1.PrivateKey);
			byte[] node2ProofSignature = CryptoHelper.HashAndSignBytes(UTF8Encoding.UTF8.GetBytes(node2Proof), node2.PrivateKey);

			// Nodes send iota transaction with their mixed salt as hash so that client can find the proof
			// Nodes include their public key in the transaction
			// Client finds the proofs and verifies storage
			bool node1Verified = CryptoHelper.VerifySignedHash(UTF8Encoding.UTF8.GetBytes(node1Proof), node1ProofSignature, node1.PublicKey);
			bool node2Verified = CryptoHelper.VerifySignedHash(UTF8Encoding.UTF8.GetBytes(node2Proof), node2ProofSignature, node2.PublicKey);


			//Proposal for payments without contracts:
			/*
			 * Client pays whichever amount of nodes that have provided with proof based on how much redundancy is required.
			 * nodes that do not receive payments simply drop the data, to prevent freeloading nodes could choose to not serve the data before payment for that epoch.
			 * /




			// ====== ------ Tangle Storage Test Application  ------ ========

			//RestIotaRepository opacityTest = new RestIotaRepository(new RestClient("https://prodiota1.opacitynodes.com:14265"));//
			//var testA = opacityTest.GetNodeInfo();
			//string A = JsonConvert.SerializeObject(testA);

			////opacityTest.
			//var res = opacityTest.GetLatestInclusion(new List<Hash>());
			////var testB = opacityTest.GetNeighbors();
			////string B = JsonConvert.SerializeObject(testB);



			//repository = new RestIotaRepository(new RestClient("http://node.deviceproof.org:14265"));
			///*			
			//var nodeInfo = repository.GetNodeInfo();
			//var neighbours = repository.GetNeighbors();
			//*/

			//byte[] raw = GetFile("C:\\Users\\Mutsi\\Desktop\\oystericon_idle.png");
			//List<Byte[]> chunks = GetChunks(raw).ToList();
			////StitchAndSave(chunks);

			//List<Hash> hashes = new List<Hash>();
			//AttachChunk(chunks.First());
			///*
			//Parallel.ForEach(chunks, (chunk) =>
			//{
			//	hashes.Add(AttachChunk(chunk));
			//});
			//foreach (byte[] chunk in chunks)
			//{
			////	hashes.Add(AttachChunk(chunk));
			//}*/
		}

		static byte[] GetFile(string path)
		{
			return File.ReadAllBytes(path);
		}

		static IEnumerable<byte[]> GetChunks(byte[] rawData)
		{
			List<byte[]> chunks = new List<byte[]>();

			int taken = 0;
			for (int i = 0; i < rawData.Length; i += CHUNK_SIZE_BYTES)
			{
				int remaining = Math.Min(CHUNK_SIZE_BYTES, rawData.Length - 1 - i);
				chunks.Add(rawData.Skip(i).Take(remaining).ToArray());

			}
			return chunks;
		}

		static void StitchAndSave(IEnumerable<byte[]> chunks)
		{
			byte[] ret = new byte[chunks.Sum(x => x.Length)];
			int offset = 0;
			foreach (byte[] data in chunks)
			{
				Buffer.BlockCopy(data, 0, ret, offset, data.Length);
				offset += data.Length;
			}

			File.WriteAllBytes("./test.png", ret);
		}

		static Hash AttachChunk(byte[] chunk)
		{
			var bundle = new Bundle();
			bundle.AddTransfer(new Transfer
			{
				Address = new Address(Hash.Empty.Value),
				Tag = new Tag("MUTSI"),
				Timestamp = Timestamp.UnixSecondsTimestamp,
				Message = TryteString.FromBytes(chunk)
			});

			bundle.Finalize();
			bundle.Sign();

			// see Getting Started to see how a repository is created
			var result = repository.SendTrytes(bundle.Transactions);

			return bundle.Hash;
		}
	}
}
