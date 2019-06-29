package src.java; /**
 * src.java.Decrypt.java
 * version : ak
 * Revision: $log ak$
 */

import src.java.utils.Utils;

/**
 * This program is an implementation of block cipher Speck.
 * It decrypts  the given ciphertext by XORing with key generated 
 * from 22 round key scheduler
 * 
 * @author  Ajinkya Kale
 *
 */

public class Decrypt {

	short [] k0= new short[22];  // stores subkeys
	short [] l0 =new short [22]; // stores L0 values
	short [] l1 = new short[22]; // stores L1 values
	short [] l2 = new short [22]; // stores L2 values
	byte[] key; // stoes key
	byte[] plaintext; // stores plaintext 
	
	/**
	 * Constructor initilizing key and plaintext
	 */
	public Decrypt(byte [] key, byte []plaintext) {
		this.key= key;
		this.plaintext=plaintext;
	}


	/**
	 * This method sets the initial values of the key k0,lo,l1,l2
	 */

	public void setKey(byte[] key) {
		long key_1= Utils.packLongBigEndian(key, 0);
		k0[0]= (short)(key_1 & 0x000000000000FFFFL);
		l0[0]= (short)((key_1 & 0x00000000FFFF0000L)>>16);
		l1[0]= (short)((key_1 & 0x0000FFFF00000000L)>>32);
		l2[0]= (short)((key_1 & 0xFFFF000000000000L)>>48);
	}

	/**
	 * returns blocksize 
	 */

	public int blockSize() {
		return 32;
	}

	/**
	 * returns keysize 
	 */

	public int keySize() {
		return 64;
	}

	/**
	 * This method produceds 22 subkeys required to generate ciphertext
	 * 
	 */
	public void keySchedule(){
		int count=1;
		int l=1,k=1,m=1,j=1;
		int first=0, second=0, third=0;
		for(int i=0; i<21;i++){
			if( count==1){
				l0[l]= (short)((k0[i] + l_right_rotate(l0[first]))^ (short)i);
				k0[j] = (short)(  k_left_rotate(k0[i])^ l0[l]);
				l++;
				j++;
				first++;
			}

			if(count ==2){
				l1[k]= (short) ((k0[i] +  l_right_rotate(l1[second]))^ (short)i);
				k0[j] =(short) ( k_left_rotate(k0[i]) ^ l1[k]);
				k++;
				j++;
				second++;
			}
			if(count == 3){
				l2[m]= (short) ((k0[i] +l_right_rotate(l2[third]))^(short)i);
				k0[j]= (short) ((k_left_rotate(k0[i])) ^ l2[m]);
				m++;
				j++;
				third++;
			}
			count++;
			if(count>3){
				count=1;
			}
		}
	}

	/**
	 * This method perfoms right rotation by 7
	 * @param s
	 * @return temp
	 */
	private short l_right_rotate(short s) {
		short x= (short) ((s& 0x0000FFFF)>>7);
		short y= (short) ((s& 0x0000FFFF)<<9);
		short temp = (short) (y|x);
		return temp;
	}

	/**
	 * This method performs left rotation by 2
	 * @param s
	 * @return temp
	 */
	private short k_left_rotate(short s){
		short y= (short)( (s& 0x0000FFFF)<<2);
		short x= (short)((s& 0x0000FFFF)>>14);
		short temp = (short) (y|x);
		return temp;
	}

	/**
	 * This method performs right rotate vy 2 positions
	 * @param s
	 * @return temp
	 */
	private short right_rotate_by_2(short s){
		short y= (short)( (s& 0x0000FFFF)>>2);
		short x= (short)((s& 0x0000FFFF)<<14);
		short temp = (short) (y|x);
		return temp;
	}

	/**
	 * This method perform left rotation by 7 
	 * @param s
	 * @return temp
	 */
	private short left_rotate_by_7(short s){
		short x= (short) ((s& 0x0000FFFF)<<7);
		short y= (short) ((s& 0x0000FFFF)>>9);
		short temp = (short) (y|x);
		return temp;
	}

	/**
	 * This method decrypts the ciphertext using the subkey in reverse order.
	 * Decryption consists of 22 rounds
	 */

	public void decrypt(byte [] text){
		int dec=0;
		int ciphertext = Utils.packIntBigEndian(text, 0);
		short x = (short) ((ciphertext & 0xFFFF0000)>>16);
		short y = (short) ((ciphertext & 0x0000FFFF));

		for(int i=21; i>=0 ; i--){
			short value1= (short)(x ^ y);
			y= right_rotate_by_2((short)(x ^ y));
			short value2= (short) (x ^ k0[i]);
			short value3 = (short)((x ^ k0[i])- y);
			x= (short)(left_rotate_by_7((short)((x ^ k0[i])- y)));
			dec = x<<16 | (  y&0x0000FFFF);

		}
		byte[] temp2 = Utils.toByteArray(Utils.toString(dec));
		text[0]= temp2[0];
		text[1]= temp2[1];
		text[2]= temp2[2];
		text[3]= temp2[3];

	}

}
