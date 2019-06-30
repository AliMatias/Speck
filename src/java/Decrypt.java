package src.java;

import src.java.utils.Utils;

/**
 * Implementación de la desencriptación de Speck 32/64
 *
 */

public class Decrypt {

	short [] k0= new short[22];  // subkeys
	short [] l0 =new short [22]; // valores L0
	short [] l1 = new short[22]; // valores L1
	short [] l2 = new short [22]; // valores L2
	byte[] key; // key
	byte[] plaintext; // plaintext

	public Decrypt(byte [] key, byte []plaintext) {
		this.key= key;
		this.plaintext=plaintext;
	}


	/**
	 * Setear los valores iniciales de la key K0,L0,L1,L2
	 */

	public void setKey(byte[] key) {
		long key_1= Utils.packLongBigEndian(key, 0);
		k0[0]= (short)(key_1 & 0x000000000000FFFFL);
		l0[0]= (short)((key_1 & 0x00000000FFFF0000L)>>16);
		l1[0]= (short)((key_1 & 0x0000FFFF00000000L)>>32);
		l2[0]= (short)((key_1 & 0xFFFF000000000000L)>>48);
	}

	/**
	 * Producir las 22 keys necesarias para generar el ciphertext
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
	 * Shift Right por 7
	 */
	private short l_right_rotate(short s) {
		short x= (short) ((s& 0x0000FFFF)>>7);
		short y= (short) ((s& 0x0000FFFF)<<9);
		return (short) (y|x);
	}

	/**
	 * Shift Left por 2
	 */
	private short k_left_rotate(short s){
		short y= (short)( (s& 0x0000FFFF)<<2);
		short x= (short)((s& 0x0000FFFF)>>14);
		return (short) (y|x);
	}

	/**
	 * Shoft Right por 2
	 */
	private short right_rotate_by_2(short s){
		short y= (short)( (s& 0x0000FFFF)>>2);
		short x= (short)((s& 0x0000FFFF)<<14);
		return (short) (y|x);
	}

	/**
	 * Shift Left por 7
	 */
	private short left_rotate_by_7(short s){
		short x= (short) ((s& 0x0000FFFF)<<7);
		short y= (short) ((s& 0x0000FFFF)>>9);
		return (short) (y|x);
	}

	/**
	 * Desencriptar el ciphertext usando la subkey en orden inverso.
	 * consiste de 22 rondas
	 */

	public void decrypt(byte [] text){
		int dec=0;
		int ciphertext = Utils.packIntBigEndian(text, 0);
		short x = (short) ((ciphertext & 0xFFFF0000)>>16);
		short y = (short) (ciphertext & 0x0000FFFF);

		for(int i=21; i>=0 ; i--){
			y= right_rotate_by_2((short)(x ^ y));
			x= left_rotate_by_7((short)((x ^ k0[i])- y));
			dec = x<<16 | (  y&0x0000FFFF);

		}
		byte[] temp2 = Utils.toByteArray(Utils.toString(dec));
		text[0]= temp2[0];
		text[1]= temp2[1];
		text[2]= temp2[2];
		text[3]= temp2[3];

	}

}
