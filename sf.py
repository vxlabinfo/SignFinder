# coding=utf8

'''
SignFinder - Tool for easy clean PE32 from AV signature 

Reqiure - https://github.com/erocarrera/pefile
Install - pip install pefile.zip

'''

__author__   = 'Auth0r'
__site__     = 'vxlab.info'
__twitter__  = 'https://twitter.com/vxlab_info/'
__version__  = '07.05.2016'

import os
import sys
import pefile
import struct

#------------------------------------------------
# common functions
#------------------------------------------------

def DieWithError(err):
	sys.exit('[!] '+err)
	
def SetHome(path):
	home = os.path.realpath(os.path.dirname(path))
	os.chdir(home)
	
def ReadFile(path):
	if os.path.isfile(path):
		f = open(path, 'rb')	
		data = f.read()
		f.close()
		return data
	else:
		DieWithError('file '+path+' not found!')

def SaveFile(path,data):
	f = open(path, 'wb')
	f.write(data)
	f.close()
		
def CreateOutputFolder(path):
	name = os.path.basename(path)
	tmp = name.split('.')
	name = tmp[0]
	dir_name = name+'_SignFinder'
	if not os.path.isdir(dir_name):
		os.mkdir(dir_name)
	return dir_name

def PrintLogo():
	print '\n[------------------------]'
	print ' SignFinder by ' + __site__
	print ' Version on ' + __version__
	print '[------------------------]\n'

#------------------------------------------------
# utils..
#------------------------------------------------
def CleanHeaderStruct(file_data, file_offset, dir_name, stucture):
	offset_list = pefile_StructToOffsets(stucture)
	struct_name = offset_list[0]
	for i in offset_list[1]:
		tmp = i.split(',')
		offset = int(tmp[0])
		size   = int(tmp[1])
		name   = struct_name+'-'+ tmp[2]
		# forbid - e_lfanew and e_magic
		if tmp[2]!='e_lfanew' and tmp[2]!='e_magic':
			CleanFileOffset(file_data, dir_name, file_offset + offset, size, name)	
						
def SaveClean(file_name, dir_name, file_data):
	file_path = '{}\\{}.clean'.format(dir_name, file_name)
	SaveFile(file_path, file_data)
	
#------------------------------------------------
# replacement functions
#------------------------------------------------
	
def ReplaceByte(data, offset, window_size, window_byte):
	r = window_byte * window_size
	new_data = data[:offset] + r  + data[offset+window_size:]
	return new_data

def CleanFileOffset(file_data, dir_name, offset, size, file_name):
		new_data = ReplaceByte(file_data, offset, size, '\x00')
		SaveClean(file_name, dir_name, new_data)
		
def ReplaceByteString(data, offset, new_bytes):
	new_data = data[:offset] + new_bytes  + data[offset+len(new_bytes):]
	return new_data
	
#------------------------------------------------
# pefile stuff
#------------------------------------------------

# convert pefile struct to our own offset-based format
# like (field_offset,field_size,field_name)
def pefile_StructToOffsets(structure):
	offset_list = list()
	tmp_list = list()
	offset = 0
	for s in structure[1]:
		if s is not None:
			tmp = s.split(',')
			name = tmp[1]
			format = str(tmp[0]) 
			size = struct.calcsize(format)
			tmp_list.append("{},{},{}".format(offset, size, name))
			offset += size
	offset_list = (structure[0], tmp_list)
	return offset_list
		
# get interesting info from pefile
def GetPeInfo(file_data):
	try:
		pe =  pefile.PE(data=file_data, fast_load = True)
		info = dict() 
		section_list = list()
		section_num = 0
		
		for section in pe.sections:
			name = section.Name.replace('\x00','')
			name = '[{}]{}'.format(section_num,name)
			section_tmp = {'name':name, 'offset':section.PointerToRawData, 'size':section.SizeOfRawData}
			section_list.append(section_tmp)
			section_num += 1
		
		info['sections'] = section_list

		import_offset = pe.get_offset_from_rva(pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress)
		import_dir = (import_offset, pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size)
		info['import'] = import_dir
		
		ep_offset = pe.get_offset_from_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
		info['ep'] = ep_offset
		
		info['optional_offset'] = pe.OPTIONAL_HEADER.get_file_offset()
		
		return info

	except Exception, e:
		DieWithError(str(e))

			
#------------------------------------------------
# work modes
#------------------------------------------------

def mode_fast(file_data, dir_name, pe_info):

	# replace code on entry point 
	new_byte = '\xCC\xC3' # INT3 RET
	new_data = ReplaceByteString(file_data,pe_info['ep'],new_byte)
	SaveClean('EMUL', dir_name, new_data)
	
	# delete import
	new_data = ReplaceByte(file_data, pe_info['import'][0], pe_info['import'][1], '\x00')
	SaveClean('IMPORT', dir_name, new_data)
	
	# clean sections data one by one
	for sect in pe_info['sections']:
		new_data = ReplaceByte(file_data, sect['offset'], sect['size'], '\x00')
		SaveClean('SECTION{}'.format(sect['name']), dir_name, new_data)
		
	# clean ALL sections
	new_data = file_data
	for sect in pe_info['sections']:
		new_data = ReplaceByte(new_data, sect['offset'], sect['size'], '\x00')
	SaveClean('ALL_SECTION', dir_name, new_data)
		
	# cleanse all sections but one
	for sect in pe_info['sections']:
		new_data = file_data
		for sect2 in pe_info['sections']:
			if sect2['name'] != sect['name']:
				new_data = ReplaceByte(new_data, sect2['offset'], sect2['size'], '\x00')
		SaveClean('ALL_SECTION_NOT{}'.format(sect['name']), dir_name, new_data)
		
	print "[-] Fast mode - done" 


def mode_header(file_data, dir_name, pe_info):
	# start from DosHeader
	CleanHeaderStruct(file_data, 0, dir_name, pefile.PE.__IMAGE_DOS_HEADER_format__)
	# then OptionalHeader
	CleanHeaderStruct(file_data, pe_info['optional_offset'], dir_name, pefile.PE.__IMAGE_OPTIONAL_HEADER_format__)
	print "[-] Header mode - done" 
	

# divide the section into 100 pieces and cut them one by one
def mode_section(file_data, dir_name, pe_info, sect_num):
	found = False
	sect_i = 0 
	for sect in pe_info['sections']:
		if sect_num == sect_i:
			part_num = 100
			part_size = sect['size'] / part_num
			
			last_part_size = sect['size'] % part_num
			offset = sect['offset']
			
			for i in range(part_num):
				file_name = 'SECTION[{}]_{}_PART-{}-{}'.format(sect_num, i, offset, part_size)
				CleanFileOffset(file_data, dir_name, offset, part_size, file_name)
				offset += part_size
				found = True
			
			if last_part_size > 0:
				file_name = 'SECTION[{}]_{}_PART-{}-{}'.format(sect_num, part_num, offset, last_part_size)
				CleanFileOffset(file_data, dir_name, offset, last_part_size, file_name)
		
		sect_i += 1
		
	if found:
		print "[-] Section mode - done"  
		return
	else:
		DieWithError('invalid section number')


def mode_manual(file_data, dir_name, file_offset, offset_size, part_num):

	part_size = offset_size / part_num
	last_part_size = offset_size % part_num
	offset = file_offset
	
	for i in range(part_num):
		file_name = 'MANUAL_{}_PART-{}-{}'.format( i, offset, part_size)
		CleanFileOffset(file_data, dir_name, offset, part_size, file_name)
		offset += part_size
		
	if last_part_size > 0:
		file_name = 'MANUAL_{}_PART-{}-{}'.format( part_num, offset, last_part_size)
		CleanFileOffset(file_data, dir_name, offset, last_part_size, file_name)
		
	print "[-] Manual mode - done"  
	
	
def mode_manual2(file_data, dir_name, file_offset, offset_size, window_size):

	offset = file_offset
	max_offset = offset + offset_size - window_size
	i = 0
	while 1:
		if offset > max_offset:
			break
		file_name = 'MANUAL2_{}_PART-{}-{}'.format( i, offset, window_size)
		CleanFileOffset(file_data, dir_name, offset, window_size, file_name)
		offset += 1
		i += 1
	print "[-] Manual2 mode - done"   
	

#show info about pe struct
def mode_info(pe_info):
	str = ''
	for s in pe_info['sections']:
		str += '{}\t{}\t{}\n'.format(s['name'], s['offset'], s['size'])
	print (str)
	
#------------------------------------------------
# control functions
#------------------------------------------------

def main():
	PrintLogo()

	if len(sys.argv)>=3:
		mode = sys.argv[1]
		file_path = sys.argv[2]
		
		SetHome(file_path)
		dir_name = CreateOutputFolder(file_path)
		file_data = ReadFile(file_path)
		pe_info = GetPeInfo(file_data)
		
		if mode=='fast':
			mode_fast(file_data, dir_name, pe_info)

		elif mode=='info':
			mode_info(pe_info)

		elif mode=='head':
			mode_header(file_data, dir_name, pe_info)			
	
		elif mode=='sect':
			if len(sys.argv)==4:
				sect_num = int(sys.argv[3])
				mode_section(file_data, dir_name, pe_info, sect_num)
			else:
				DieWithError('lost sect param')
		elif mode=='man':
			if len(sys.argv)==6:
				file_offset = int(sys.argv[3])
				offset_size = int(sys.argv[4])
				part_num    = int(sys.argv[5])
				mode_manual(file_data, dir_name, file_offset, offset_size, part_num)
			else:
				DieWithError('lost man param')
				
		elif mode=='man2':
			if len(sys.argv)==6:
				file_offset = int(sys.argv[3])
				offset_size = int(sys.argv[4])
				window_size    = int(sys.argv[5])
				mode_manual2(file_data, dir_name, file_offset, offset_size, window_size)
			else:
				DieWithError('lost man param')			
		else:
			DieWithError('invalid mode')
	else:
		print """
USAGE:	SF.py mode param"
EXAMPLE:
	SF.py fast path_to_exe 
	SF.py head path_to_exe 
	SF.py sect path_to_exe section_number
	SF.py man path_to_exe offset size part_num
	SF.py man2 path_to_exe offset size window_size
	SF.py info path_to_exe"""

if __name__ == '__main__':
	main()
