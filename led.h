/* 
 *	Copyright (c) 2014. All rights are reserved by Jian Guo.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL WE
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, OR CONSEQUENTIAL 
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, 
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OF THE 
 * SOFTWARE.
 * 
 * Contact: Jian Guo, ntu.guo@gmail.com
 */


void LED_enc(unsigned char* input, const unsigned char* userkey, int ksbits);
void LED80_enc(unsigned char* input, const unsigned char* userkey);

void AddConstants(unsigned char state[4][4], int r);
void SubCell(unsigned char state[4][4]);
void ShiftRow(unsigned char state[4][4]);
void MixColumn(unsigned char state[4][4]);
unsigned char FieldMult(unsigned char a, unsigned char b);

void invShiftRow(unsigned char state[4][4]);
void invMixColumn(unsigned char state[4][4]);

