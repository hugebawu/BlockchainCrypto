package com.example.encryption.ecceg;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import cn.edu.ncepu.crypto.encryption.ecceg.ECC;
import cn.edu.ncepu.crypto.encryption.ecceg.ECCEG;
import cn.edu.ncepu.crypto.encryption.ecceg.FileReader;
import cn.edu.ncepu.crypto.encryption.ecceg.Pair;
import cn.edu.ncepu.crypto.encryption.ecceg.ECCPoint;

public class Main2 {
	public static void main(String[] args) {
		BigInteger a = new BigInteger("1"), b = new BigInteger("1"), p = new BigInteger("2000003");
		ECC ecc = new ECC(a, b, p);
		ECCEG ecceg = new ECCEG(ecc, ecc.getBasePoint());

		Scanner sc = new Scanner(System.in);
		FileReader fr = new FileReader();
		int pilihan;
		do {
			System.out.println("Menu");
			System.out.println("1. Generate Kunci Privat dan Kunci Publik");
			System.out.println("2. Enkripsi File");
			System.out.println("3. Dekripsi File");
			System.out.println("4. Exit");
			System.out.print("Pilihan: ");
			pilihan = Integer.parseInt(sc.nextLine());
			if (pilihan == 1) {
				System.out.print("Private key: ");
				System.out.println(ecceg.getPrivateKey());
				System.out.print("Public key: ");
				System.out.println(ecceg.getPublicKey());
				ecceg.savePrivateKey("key.pri");
				System.out.println("Private key saved to key.pri");
				ecceg.savePublicKey("key.pub");
				System.out.println("Public key saved to key.pub");
			} else if (pilihan == 2) {
				int pilihanEnkripsi;
				do {
					System.out.println("Source kunci publik");
					System.out.println("1. Masukan pengguna");
					System.out.println("2. File kunci publik");
					System.out.print("Pilihan: ");
					pilihanEnkripsi = Integer.parseInt(sc.nextLine());
					if (pilihanEnkripsi < 1 && pilihanEnkripsi > 2)
						System.out.println("Pilihan salah, masukan yang diterima 1 atau 2");
					else if (pilihanEnkripsi == 1) {
						System.out.print("Masukan kunci publik nilai pertama: ");
						String nilaiPertama = sc.nextLine();
						System.out.print("Masukan kunci publik nilai kedua: ");
						String nilaiKedua = sc.nextLine();
						ECCPoint kunciPublik = new ECCPoint(new BigInteger(nilaiPertama), new BigInteger(nilaiKedua));
						ecceg.setPublicKey(kunciPublik);
					} else {
						System.out.print("Masukan nama file kunci publik: ");
						String fileKunciPublic = sc.nextLine();
						System.out.println(fileKunciPublic);
						ecceg.loadPublicKey(fileKunciPublic);
					}
					int pilihanSourcePesan;
					do {
						System.out.println("Source teks pesan");
						System.out.println("1. Masukan pengguna");
						System.out.println("2. File teks pesan");
						System.out.print("Pilihan: ");
						pilihanSourcePesan = Integer.parseInt(sc.nextLine());
						List<Pair<ECCPoint, ECCPoint>> enc = new ArrayList<Pair<ECCPoint, ECCPoint>>();
						if (pilihanSourcePesan < 1 && pilihanSourcePesan > 2)
							System.out.println("Pilihan salah, masukan yang diterima 1 atau 2");
						else if (pilihanSourcePesan == 1) {
							System.out.print("Masukan pesan: ");
							String pesan = sc.nextLine();
							byte[] read = pesan.getBytes();
							enc = ecceg.encryptBytes(read);
						} else {
							System.out.print("Masukan nama file: ");
							String fileTeks = sc.nextLine();
							byte[] read = fr.fileToBytes(fileTeks);
							enc = ecceg.encryptBytes(read);
						}
						System.out.print("Cipher text: ");
						for (Pair<ECCPoint, ECCPoint> pp : enc) {
							System.out.print(String.format("%02x%02x%02x%02x", pp.left.x.intValue(),
									pp.left.y.intValue(), pp.right.x.intValue(), pp.right.y.intValue()));
						}
						System.out.println();
						System.out.println("Enkripsi disimpan dalam file enkripsi.txt");
						fr.savePointsToFile("enkripsi.txt", enc);
					} while (pilihanSourcePesan < 1 && pilihanSourcePesan > 2);
				} while (pilihanEnkripsi < 1 && pilihanEnkripsi > 2);
			} else if (pilihan == 3) {
				int pilihanEnkripsi;
				do {
					System.out.println("Source kunci privat");
					System.out.println("1. Masukan pengguna");
					System.out.println("2. File kunci privat");
					System.out.print("Pilihan: ");
					pilihanEnkripsi = Integer.parseInt(sc.nextLine());
					if (pilihanEnkripsi < 1 && pilihanEnkripsi > 2)
						System.out.println("Pilihan salah, masukan yang diterima 1 atau 2");
					else if (pilihanEnkripsi == 1) {
						System.out.print("Masukan kunci privat: ");
						BigInteger kunciPrivat = new BigInteger(sc.nextLine());
						ecceg.setPrivateKey(kunciPrivat);
					} else {
						System.out.print("Masukan nama file kunci privat: ");
						String fileKunciPrivat = sc.nextLine();
						ecceg.loadPrivateKey(fileKunciPrivat);
					}
					System.out.print("Masukan nama file teks cipher: ");
					String fileTeksCipher = sc.nextLine();
					List<Pair<ECCPoint, ECCPoint>> read_enc = fr.loadPointsFromFile(fileTeksCipher);
					List<ECCPoint> read_dec = ecceg.decrypt(read_enc);
					System.out.println("Hasil Dekripsi: ");
					for (ECCPoint pp : read_dec)
						System.out.print((char) ecc.pointToInt(pp).byteValue());
					System.out.println();
				} while (pilihanEnkripsi < 1 && pilihanEnkripsi > 2);
			}
		} while (pilihan != 4);
	}
}