# coding=utf8

'''
SignFinder - Tool for easy clean PE32 from AV signature 

Reqiure - https://github.com/erocarrera/pefile
Install - pip install pefile.zip

'''

__author__   = 'Auth0r'
__site__     = 'vxlab.info'
__twitter__  = 'https://twitter.com/vxlab_info/'
__version__  = '27.07.2016'

import os
import sys
import pefile
import struct
import argparse

#------------------------------------------------
# common functions
#------------------------------------------------

def DieWithError(err):
	sys.exit('[!] '+err)
	
def SetHome(path):
	home = os.path.realpath(os.path.dirname(path))
	os.chdir(home)
	
def get_file_data(path):
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
		
def get_output_dir(path,mode,opt=None):
	name = os.path.basename(path)
	tmp = name.split('.')
	name = tmp[0]
	dir_name = "{} [{}]".format(name,mode.__name__)
	if opt is not None:
		dir_name = "{} [{}] [{}]".format(name,mode.__name__,opt)		
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
		
def get_section_info(pe): 
	section_list = list()
	section_num = 0
	for section in pe.sections:
		name = section.Name.replace('\x00','')
		name = '[{}]{}'.format(section_num,name)
		section_tmp = {'name':name, 'offset':section.PointerToRawData, 'size':section.SizeOfRawData}
		section_list.append(section_tmp)
		section_num += 1
	return section_list

def get_headers_info(pe): 
	info = {}
	ep_offset = pe.get_offset_from_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
	info['ep'] = ep_offset
	info['optional_offset'] = pe.OPTIONAL_HEADER.get_file_offset()
	return info

def get_directories_info(pe): 
	info = {}
	import_offset = pe.get_offset_from_rva(pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress)
	import_dir = (import_offset, pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size)
	info['import'] = import_dir
		
	import_offset = pe.get_offset_from_rva(pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].VirtualAddress)
	import_dir = (import_offset, pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size)
	info['resource'] = import_dir
	
	import_offset = pe.get_offset_from_rva(pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress)
	import_dir = (import_offset, pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size)
	info['reloc'] = import_dir
	return info
	
#need PE(fast_load=False)
def get_iat_info(pe): 
	info = {}
	info['lib'] = list()
	info['iat'] = list()
	for entry in pe.DIRECTORY_ENTRY_IMPORT:
		dll = entry.dll
		
		if dll not in info['lib']:
			info['lib'].append(dll)
		
		for imp in entry.imports:
			iat = dict() 
			iat['addr'] = hex(imp.address)
			iat['name_offset'] = hex(imp.name_offset)
			iat['name'] = imp.name
			iat['dll'] = dll
			info['iat'].append(iat)	
	return info

#------------------------------------------------
# working modules
#------------------------------------------------

def mode_fast(param,args):
	dir_name = get_output_dir(param['path'],mode_fast)
	file_data = param['data']
	
	# replace code on entry point 
	headers = get_headers_info(param['pe'])
	new_byte = '\xCC\xC3' # INT3 RET
	new_data = ReplaceByteString(file_data,headers['ep'],new_byte)
	SaveClean('EMUL', dir_name, new_data)
	
	# delete import
	dir = get_directories_info(param['pe'])
	new_data = ReplaceByte(file_data, dir['import'][0], dir['import'][1], '\x00')
	SaveClean('IMPORT', dir_name, new_data)
	
	sections = get_section_info(param['pe'])
	
	# clean sections data one by one
	for sect in sections:
		new_data = ReplaceByte(file_data, sect['offset'], sect['size'], '\x00')
		SaveClean('SECTION{}'.format(sect['name']), dir_name, new_data)
		
	# clean ALL sections
	new_data = file_data
	for sect in sections:
		new_data = ReplaceByte(new_data, sect['offset'], sect['size'], '\x00')
	SaveClean('ALL_SECTION', dir_name, new_data)
		
	# cleanse all sections but one
	for sect in sections:
		new_data = file_data
		for sect2 in sections:
			if sect2['name'] != sect['name']:
				new_data = ReplaceByte(new_data, sect2['offset'], sect2['size'], '\x00')
		SaveClean('ALL_SECTION_NOT{}'.format(sect['name']), dir_name, new_data)
		
	print "[-] Fast mode - done" 

#------------------------------------------------
#show info about pe struct
def mode_info(param,args):
	str = ''
	for s in get_section_info(param['pe']):
		str += '{}\t{}\t{}\n'.format(s['name'], s['offset'], s['size'])
	print (str)

#------------------------------------------------	
def mode_header(param,args):
	dir_name = get_output_dir(param['path'],mode_header)
	file_data = param['data']
	# start from DosHeader
	CleanHeaderStruct(file_data, 0, dir_name, pefile.PE.__IMAGE_DOS_HEADER_format__)
	# then OptionalHeader
	headers = get_headers_info(param['pe'])
	CleanHeaderStruct(file_data, headers['optional_offset'], dir_name, pefile.PE.__IMAGE_OPTIONAL_HEADER_format__)
	print "[-] Header mode - done" 

#------------------------------------------------
# divide the section into 100 pieces and cut them one by one
def mode_section(param,args):
	sect_num  = args.section_number
	sections  = get_section_info(param['pe'])
	file_data = param['data']
	part_num = args.p

	opt = "{}-{}".format(sect_num,part_num)
	dir_name  = get_output_dir(param['path'],mode_section,opt)
		
	found = False
	sect_i = 0 
	for sect in sections:
		if sect_num == sect_i:
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

#------------------------------------------------
def mode_manual(param,args):
	offset  = args.offset
	offset_size  = args.size
	part_num  = args.part_number
	file_data = param['data']
	
	opt = "{}-{}-{}".format(offset,offset_size,part_num)
	dir_name  = get_output_dir(param['path'],mode_manual,opt)
	
	part_size = offset_size / part_num
	last_part_size = offset_size % part_num
	
	for i in range(part_num):
		file_name = 'MANUAL_{}_PART-{}-{}'.format( i, offset, part_size)
		CleanFileOffset(file_data, dir_name, offset, part_size, file_name)
		offset += part_size
		
	if last_part_size > 0:
		file_name = 'MANUAL_{}_PART-{}-{}'.format( part_num, offset, last_part_size)
		CleanFileOffset(file_data, dir_name, offset, last_part_size, file_name)
		
	print "[-] Manual mode - done"  
 
#------------------------------------------------
def mode_manual2(param,args):
	offset  = args.offset
	offset_size  = args.size
	window_size  = args.window_size
	file_data = param['data']
	
	opt = "{}-{}-{}".format(offset,offset_size,window_size)
	dir_name  = get_output_dir(param['path'],mode_manual2,opt)
	
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

#------------------------------------------------
# control functions
#------------------------------------------------
	
def main():
	PrintLogo()

	parser = argparse.ArgumentParser()
	parser.add_argument("path")
	subparsers = parser.add_subparsers()
	
	parser_info = subparsers.add_parser('info', help='section offset and size')
	parser_info.set_defaults(func=mode_info)
	
	parser_fast = subparsers.add_parser('fast', help='localization signature place')
	parser_fast.set_defaults(func=mode_fast)
		
	parser_head = subparsers.add_parser('head', help='test Optional/Dos Headers')
	parser_head.set_defaults(func=mode_header)
	
	parser_sect = subparsers.add_parser('sect', help='search signatures in section')
	parser_sect.set_defaults(func=mode_section,p=100)
	parser_sect.add_argument("section_number", type=int)
	parser_sect.add_argument("-p", type=int, help='part_number')
		
	parser_man  = subparsers.add_parser('man', help='manual mode')
	parser_man.set_defaults(func=mode_manual)
	parser_man.add_argument("offset", type=int)
	parser_man.add_argument("size", type=int)
	parser_man.add_argument("part_number", type=int)
	
	parser_man2 = subparsers.add_parser('man2', help='manual mode two')
	parser_man2.set_defaults(func=mode_manual2)
	parser_man2.add_argument("offset", type=int)
	parser_man2.add_argument("size", type=int)
	parser_man2.add_argument("window_size", type=int)	
	
	
	args = parser.parse_args()
	path = args.path
	
	if not os.path.isfile(path):
		DieWithError("File not found")
	data = get_file_data(path)
		
	try:
		pe_info = pefile.PE(data = data, fast_load=True)
	except pefile.PEFormatError, e:
		DieWithError("PEFormatError:" + e)
	
	SetHome(path)
	param = {}
	param['path'] = path
	param['data'] = data
	param['pe'] = pe_info
	args.func(param,args)
	sys.exit()
	
if __name__ == '__main__':
	main()
