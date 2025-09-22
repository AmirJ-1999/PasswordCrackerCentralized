using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text; // [OPDATERET]
using PasswordCrackerCentralized.model;
using PasswordCrackerCentralized.util;

namespace PasswordCrackerCentralized
{
    public class Cracking
    {
        // [OPDATERET] SHA1 som i opgaven (svagt kryptografisk, men ok til lab)
        private readonly HashAlgorithm _messageDigest = new SHA1CryptoServiceProvider();

        public void RunCracking()
        {
            Stopwatch stopwatch = Stopwatch.StartNew();

            List<UserInfo> userInfos = PasswordFileHandler.ReadPasswordFile("passwords.txt");
            Console.WriteLine("Password file loaded: " + userInfos.Count + " entries");

            List<UserInfoClearText> result = new List<UserInfoClearText>();

            using (FileStream fs = new FileStream("webster-dictionary-reduced.txt", FileMode.Open, FileAccess.Read))
            using (StreamReader dictionary = new StreamReader(fs, Encoding.UTF8)) // [OPDATERET]
            {
                while (!dictionary.EndOfStream)
                {
                    string dictionaryEntry = dictionary.ReadLine();
                    var partial = CheckWordWithVariations(dictionaryEntry, userInfos);
                    result.AddRange(partial);
                }
            }

            stopwatch.Stop();
            Console.WriteLine(string.Join(", ", result));
            Console.WriteLine("Out of {0} passwords, {1} were found", userInfos.Count, result.Count);
            Console.WriteLine("Time elapsed: {0}", stopwatch.Elapsed);
        }

        private IEnumerable<UserInfoClearText> CheckWordWithVariations(string dictionaryEntry, List<UserInfo> userInfos)
        {
            List<UserInfoClearText> result = new List<UserInfoClearText>();

            void CheckAdd(string candidate)
            {
                foreach (var found in CheckSingleWord(userInfos, candidate))
                    result.Add(found);
            }

            CheckAdd(dictionaryEntry);
            CheckAdd(dictionaryEntry.ToUpper());
            CheckAdd(util.StringUtilities.Capitalize(dictionaryEntry));
            CheckAdd(util.StringUtilities.Reverse(dictionaryEntry));

            for (int i = 0; i < 100; i++) CheckAdd(dictionaryEntry + i);
            for (int i = 0; i < 100; i++) CheckAdd(i + dictionaryEntry);
            for (int i = 0; i < 10; i++)
                for (int j = 0; j < 10; j++)
                    CheckAdd(i + dictionaryEntry + j);

            return result;
        }

        private IEnumerable<UserInfoClearText> CheckSingleWord(IEnumerable<UserInfo> userInfos, string possiblePassword)
        {
            byte[] passwordAsBytes = Encoding.UTF8.GetBytes(possiblePassword); // [OPDATERET]
            byte[] encryptedPassword = _messageDigest.ComputeHash(passwordAsBytes);

            List<UserInfoClearText> results = new List<UserInfoClearText>();
            foreach (UserInfo userInfo in userInfos)
            {
                if (CompareBytes(userInfo.EntryptedPassword, encryptedPassword))
                {
                    results.Add(new UserInfoClearText(userInfo.Username, possiblePassword));
                    Console.WriteLine(userInfo.Username + " " + possiblePassword);
                }
            }
            return results;
        }

        private static bool CompareBytes(IList<byte> a, IList<byte> b)
        {
            if (a == null || b == null || a.Count != b.Count) return false;
            for (int i = 0; i < a.Count; i++) if (a[i] != b[i]) return false;
            return true;
        }
    }
}
