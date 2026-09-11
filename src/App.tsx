import { Fragment, useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/tauri";
import { open as openDialog, save } from '@tauri-apps/api/dialog';
import { listen } from '@tauri-apps/api/event';
import { invoke as invokeTauri } from '@tauri-apps/api/tauri';
import { getVersion } from '@tauri-apps/api/app';
import { 
  ThemeProvider, 
  createTheme, 
  CssBaseline, 
  Container, 
  Box, 
  Tabs, 
  Tab, 
  Button, 
  TextField, 
  Checkbox, 
  FormControlLabel,   
  Paper, 
  Grid, 
  Menu, 
  MenuItem, 
  Select,
  Typography, 
  IconButton,
  LinearProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Link,
} from "@mui/material";
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import Brightness4Icon from '@mui/icons-material/Brightness4';
import Brightness7Icon from '@mui/icons-material/Brightness7';
import { Language, TranslationKey, translate } from './i18n';

type AlgorithmKey = 'md5' | 'sha1' | 'sha256' | 'sha384' | 'sha512' | 'sha3_256' | 'sha3_512' | 'blake2b' | 'blake2s' | 'blake3' | 'crc32' | 'crc64' | 'xxhash3';

function App() {
  const [language, setLanguage] = useState<Language>(() => {
    return localStorage.getItem('language') === 'es' ? 'es' : 'en';
  });
  const t = (key: TranslationKey, values?: Record<string, string>) => translate(language, key, values);

  useEffect(() => {
    localStorage.setItem('language', language);
  }, [language]);

  // Theme state with localStorage persistence
  const [isDarkMode, setIsDarkMode] = useState(() => {
    const savedTheme = localStorage.getItem('theme-mode');
    return savedTheme ? savedTheme === 'dark' : true; // Default to dark mode
  });

  // Save theme preference whenever it changes
  useEffect(() => {
    localStorage.setItem('theme-mode', isDarkMode ? 'dark' : 'light');
  }, [isDarkMode]);

  // Create theme with smooth transitions
  const theme = createTheme({
    palette: {
      mode: isDarkMode ? 'dark' : 'light',
    },
    transitions: {
      duration: {
        shortest: 150,
        shorter: 200,
        short: 250,
        standard: 300,
        complex: 375,
        enteringScreen: 225,
        leavingScreen: 195,
      },
    },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            transition: 'background-color 0.3s ease, color 0.3s ease',
          },
        },
      },
    },
  });

  const [activeTab, setActiveTab] = useState(0);
  const [filePath, setFilePath] = useState("");
  const [folderPath, setFolderPath] = useState("");
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null); 
  const [checkingUpdate, setCheckingUpdate] = useState(false);
  const [appVersion, setAppVersion] = useState('');

  useEffect(() => {
    getVersion().then(setAppVersion).catch(console.error);
  }, []);

  const [excludeEmptyFields, setExcludeEmptyFields] = useState(() => {
    return localStorage.getItem('exclude-empty-fields') !== 'false';
  });

  // Save changes to exclude empty fields
  useEffect(() => {
    localStorage.setItem('exclude-empty-fields', String(excludeEmptyFields));
  }, [excludeEmptyFields]);

  // Dialog states
  const [aboutDialogOpen, setAboutDialogOpen] = useState(false);
  const [sponsorDialogOpen, setSponsorDialogOpen] = useState(false);
  const [alertDialogOpen, setAlertDialogOpen] = useState(false);
  const [alertMessage, setAlertMessage] = useState("");
  const [alertTitle, setAlertTitle] = useState("");
  const [alertSeverity, setAlertSeverity] = useState<'info' | 'success' | 'error'>('info');

  // Hash algorithm selection state with localStorage persistence
  const [selectedAlgorithms, setSelectedAlgorithms] = useState(() => {
    const saved = localStorage.getItem('hash-algorithms');
    const defaults = {
      md5: true,
      sha1: false, 
      sha256: false,
      sha384: false,
      sha512: false,
      sha3_256: false,
      sha3_512: false,
      blake2b: false,
      blake2s: false,
      blake3: false,
      crc32: false,
      crc64: false,
      xxhash3: false
    };
    return saved ? { ...defaults, ...JSON.parse(saved) } : defaults;
  });

  // Save preferences whenever they change
  useEffect(() => {
    localStorage.setItem('hash-algorithms', JSON.stringify(selectedAlgorithms));
  }, [selectedAlgorithms]);

  const handleAlgorithmChange = (algorithm: string, checked: boolean) => {
    setSelectedAlgorithms((prev: { [key: string]: boolean }) => ({
      ...prev,
      [algorithm]: checked
    }));
  };

  // Helper function to show themed alerts
  const showAlert = (title: string, message: string, severity: 'info' | 'success' | 'error' = 'info') => {
    setAlertTitle(title);
    setAlertMessage(message);
    setAlertSeverity(severity);
    setAlertDialogOpen(true);
  };

  useEffect(() => {
    const unlisten = listen<string[]>('tauri://file-drop', (event: { payload: string[] }) => {
      if (event.payload.length > 0) {
        const droppedFile = event.payload[0];
        setActiveTab(0);
        
        // Force recalculation even if it's the same file by temporarily clearing path
        if (droppedFile === filePath) {
          // Same file dropped - force recalculation by temporarily clearing path then setting it
          setFilePath("");
          setTimeout(() => setFilePath(droppedFile), 10);
        } else {
          // Different file - normal flow
          setFilePath(droppedFile);
        }
      }
    });

    return () => {
      unlisten.then((f: () => void) => f());
    };
  }, [filePath]);

  const handleTabChange = (_event: React.SyntheticEvent, newValue: number) => {
    setActiveTab(newValue);
  };

  const handleMenuClick = (event: React.MouseEvent<HTMLButtonElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  const handleCheckForUpdates = async () => {
    handleMenuClose();
    // show progress bar while we check
    setCheckingUpdate(true);
    try {
      const updateInfo = await invoke("check_for_updates");
      // If the updater returns an object when an update is available, treat that as update available.
      // If it returns null/undefined or an empty value, treat as up-to-date.
      if (!updateInfo) {
        showAlert('Update Check', 'Your app is up to date.');
      } else if (typeof updateInfo === 'object' && (updateInfo as any).version) {
        showAlert('Update Available', `Update available: ${(updateInfo as any).version}`);
      } else if (typeof updateInfo === 'string') {
        // If a string is returned, display a minimal message (no changelog)
        showAlert('Update Check', `Update check result: ${updateInfo}`);
      } else {
        showAlert('Update Check', 'Your app is up to date.');
      }
    } catch (error) {
      // Some updater implementations may throw when there's no update; treat as up-to-date.
      console.error('Update check failed', error);
      showAlert('Update Check', 'Your app is up to date.');
    } finally {
      setCheckingUpdate(false);
    }
  };

  const handleAbout = () => {
    handleMenuClose();
    setAboutDialogOpen(true);
  };

  const handleSponsor = async () => {
    handleMenuClose();
    setSponsorDialogOpen(true);
  };

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Container sx={{ py: 0, minHeight: '100vh' }}>
        <Box sx={{ borderBottom: 1, borderColor: 'divider', color: 'text.primary', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexDirection: 'column' }}>
          <Box sx={{ width: '100%', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Tabs value={activeTab} onChange={handleTabChange} aria-label={t('language')}>
            <Tab label={t('singleFile')} />
            <Tab label={t('folderScan')} />
            <Tab label={t('gpgVerify')} />
          </Tabs>
          <Box sx={{ display: 'flex', gap: 1 }}>
            <IconButton onClick={() => setIsDarkMode(!isDarkMode)} color="inherit">
              {isDarkMode ? <Brightness7Icon /> : <Brightness4Icon />}
            </IconButton>
            <Select
              value={language}
              onChange={(event) => setLanguage(event.target.value as Language)}
              size="small"
              variant="standard"
              aria-label={t('language')}
              sx={{ minWidth: 58 }}
            >
              <MenuItem value="en">EN</MenuItem>
              <MenuItem value="es">ES</MenuItem>
            </Select>
            <Button
              aria-controls="help-menu"
              aria-haspopup="true"
              onClick={handleMenuClick}
              variant="contained"
            >
              {t('help')}
            </Button>
          </Box>
          </Box>
          {checkingUpdate && <LinearProgress sx={{ width: '100%' }} />}
          <Menu
            id="help-menu"
            anchorEl={anchorEl}
            keepMounted
            open={Boolean(anchorEl)}
            onClose={handleMenuClose}
          >
            <MenuItem onClick={handleCheckForUpdates}>{t('checkForUpdates')}</MenuItem>
            <MenuItem onClick={handleSponsor}>{t('sponsor')}</MenuItem>
            <MenuItem onClick={handleAbout}>{t('about')}</MenuItem>
          </Menu>
        </Box>
        <TabPanel value={activeTab} index={0}>
          <SingleFileTab filePath={filePath} setFilePath={setFilePath} selectedAlgorithms={selectedAlgorithms} handleAlgorithmChange={handleAlgorithmChange} showAlert={showAlert} excludeEmptyFields={excludeEmptyFields} setExcludeEmptyFields={setExcludeEmptyFields} t={t} />
        </TabPanel>
        <TabPanel value={activeTab} index={1}>
          <FolderScanTab folderPath={folderPath} setFolderPath={setFolderPath} selectedAlgorithms={selectedAlgorithms} handleAlgorithmChange={handleAlgorithmChange} showAlert={showAlert} excludeEmptyFields={excludeEmptyFields} setExcludeEmptyFields={setExcludeEmptyFields} t={t} />
        </TabPanel>
        <TabPanel value={activeTab} index={2}>
          <GpgVerifyTab showAlert={showAlert} t={t} />
        </TabPanel>
      </Container>

      {/* About Dialog */}
      <Dialog open={aboutDialogOpen} onClose={() => setAboutDialogOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle sx={{ textAlign: 'center' }}>
          🔐 Rust Hash Sum {appVersion && `v${appVersion}`}
        </DialogTitle>
        <DialogContent>
          <Typography variant="body2" sx={{ mt: 1 }}>
            • Author: <Link href="https://github.com/oop7" target="_blank" rel="noopener">oop7</Link><br/>
            • Repository: <Link href="https://github.com/oop7/rhashsum" target="_blank" rel="noopener">github.com/oop7/rhashsum</Link><br/>
            • Sponsor: <Link href="https://github.com/sponsors/oop7" target="_blank" rel="noopener">github.com/sponsors/oop7</Link>
          </Typography>

          <Typography variant="body2" sx={{ mt: 3, fontStyle: 'italic', textAlign: 'center' }}>
            🛠️ Crafted for maximum speed, reliability, and developer ergonomics
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setAboutDialogOpen(false)} variant="contained" size="small">
            Close
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={sponsorDialogOpen} onClose={() => setSponsorDialogOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>{t('supportDevelopment')}</DialogTitle>
        <DialogContent>
          <Typography variant="body2" sx={{ mb: 1.5 }}>
            {t('githubSponsors')}: <Link href="https://github.com/sponsors/oop7" target="_blank" rel="noopener">github.com/sponsors/oop7</Link>
          </Typography>
          <Typography variant="body2" sx={{ mb: 1.5 }}>
            {t('buyMeACoffee')}: <Link href="https://www.buymeacoffee.com/oop7" target="_blank" rel="noopener">buymeacoffee.com/oop7</Link>
          </Typography>
          <Typography variant="body2">
            {t('directBankTransfer')}: {t('contactByEmail')} <Link href="mailto:oop7_support@proton.me">oop7_support@proton.me</Link>
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSponsorDialogOpen(false)} variant="contained" size="small">
            {t('close')}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Alert Dialog */}
      <Dialog
        open={alertDialogOpen}
        onClose={() => setAlertDialogOpen(false)}
        PaperProps={{
          sx: {
            backgroundColor: alertSeverity === 'success' ? 'success.main' : alertSeverity === 'error' ? 'error.main' : 'background.paper',
            color: alertSeverity === 'info' ? 'text.primary' : 'common.white',
          },
        }}
      >
        <DialogTitle>{alertTitle}</DialogTitle>
        <DialogContent>
          <Typography>{alertMessage}</Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setAlertDialogOpen(false)} variant="contained">
            OK
          </Button>
        </DialogActions>
      </Dialog>
    </ThemeProvider>
  );
}

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      id={`simple-tabpanel-${index}`}
      aria-labelledby={`simple-tab-${index}`}
      {...other}
      style={{ display: value === index ? 'block' : 'none' }}
    >
      <Box sx={{ p: 0 }}>
        {children}
      </Box>
    </div>
  );
}

interface SingleFileTabProps {
    filePath: string;
    setFilePath: (path: string) => void;
    selectedAlgorithms: { [key: string]: boolean };
    handleAlgorithmChange: (algorithm: string, checked: boolean) => void;
    showAlert: (title: string, message: string, severity?: 'info' | 'success' | 'error') => void;
    excludeEmptyFields: boolean;
    setExcludeEmptyFields: (value: boolean) => void;
    t: (key: TranslationKey, values?: Record<string, string>) => string;
}

interface GpgVerificationResult {
  valid_signature: boolean;
  fingerprint_match: boolean;
  signer: string | null;
  fingerprint: string | null;
  trust_level: string | null;
  status_lines: string[];
  message: string;
}

const SingleFileTab = ({ filePath, setFilePath, selectedAlgorithms, handleAlgorithmChange, showAlert, excludeEmptyFields, setExcludeEmptyFields, t }: SingleFileTabProps) => {
  const [md5, setMd5] = useState("");
  const [sha1, setSha1] = useState("");
  const [sha256, setSha256] = useState("");
  const [sha384, setSha384] = useState("");
  const [sha512, setSha512] = useState("");
  const [sha3_256, setSha3_256] = useState("");
  const [sha3_512, setSha3_512] = useState("");
  const [blake2b, setBlake2b] = useState("");
  const [blake2s, setBlake2s] = useState("");
  const [blake3, setBlake3] = useState("");
  const [crc32, setCrc32] = useState("");
  const [crc64, setCrc64] = useState("");
  const [xxhash3, setXxhash3] = useState("");
  const [expectedHash, setExpectedHash] = useState("");
  const [progress, setProgress] = useState<{ percent: number; bytes_read: number; total: number } | null>(null);
  const [isHashing, setIsHashing] = useState(false);
  const hashCacheRef = useRef<Record<string, Record<string, string>>>({});
  const validatedFileRef = useRef<string>("");

  // Clear hash results
  const clearHashes = () => {
    setMd5("");
    setSha1("");
    setSha256("");
    setSha384("");
    setSha512("");
    setSha3_256("");
    setSha3_512("");
    setBlake2b("");
    setBlake2s("");
    setBlake3("");
    setCrc32("");
    setCrc64("");
    setXxhash3("");
  };

  const applyHashResults = (results: Record<string, string>) => {
    setMd5(results.md5 || "");
    setSha1(results.sha1 || "");
    setSha256(results.sha256 || "");
    setSha384(results.sha384 || "");
    setSha512(results.sha512 || "");
    setSha3_256(results.sha3_256 || "");
    setSha3_512(results.sha3_512 || "");
    setBlake2b(results.blake2b || "");
    setBlake2s(results.blake2s || "");
    setBlake3(results.blake3 || "");
    setCrc32(results.crc32 || "");
    setCrc64(results.crc64 || "");
    setXxhash3(results.xxhash3 || "");
  };

  // Handle file selection: only set the path; calculation is handled by useEffect
  const handleFileSelect = async (path?: string) => {
    const selectedPath = path || await openDialog({ multiple: false });
    if (typeof selectedPath === 'string') {
      setFilePath(selectedPath);
    }
  };

  // Unified calculation: runs when file or algorithm selection changes
  useEffect(() => {
    const run = async () => {
      if (!filePath) return;
      const algorithms = Object.entries(selectedAlgorithms)
        .filter(([, v]) => v)
        .map(([k]) => k);
      if (algorithms.length === 0) return;

      const cacheForFile = hashCacheRef.current[filePath] || {};
      const missingAlgorithms = algorithms.filter((algorithm) => !cacheForFile[algorithm]);

      // Instantly render any cached values for this file.
      if (Object.keys(cacheForFile).length > 0) {
        applyHashResults(cacheForFile);
      } else {
        clearHashes();
      }

      // Nothing new to compute.
      if (missingAlgorithms.length === 0) {
        return;
      }

      setIsHashing(true);
      setProgress({ percent: 0, bytes_read: 0, total: 0 });

      try {
        // Validate the dropped/selected path is a file by calling a small Rust helper command.
        if (validatedFileRef.current !== filePath) {
          try {
            const isFile = await invokeTauri<boolean>('is_path_file', { path: filePath });
            if (!isFile) {
              showAlert(t('invalidSelection'), t('folderDropped'));
              setIsHashing(false);
              setProgress(null);
              return;
            }
            validatedFileRef.current = filePath;
          } catch (e) {
            console.error('Failed to validate path via backend', e);
            showAlert(t('error'), t('pathAccessError'));
            setIsHashing(false);
            setProgress(null);
            return;
          }
        }

        const checksums = await invoke("calculate_checksums", { filePath, algorithms: missingAlgorithms });
        const results = checksums as Record<string, string>;

        const mergedResults = { ...cacheForFile, ...results };
        hashCacheRef.current[filePath] = mergedResults;
        applyHashResults(mergedResults);
      } catch (error) {
        console.error('Hash calculation failed:', error);
        if (error !== "Cancelled") {
          showAlert(t('error'), t('hashCalculationFailed', { error: String(error) }));
        }
      } finally {
        setIsHashing(false);
        setProgress(null);
      }
    };

    run();
  }, [filePath, selectedAlgorithms]);

  // Progress event listener
  useEffect(() => {
    let unlisten: any;
    (async () => {
      unlisten = await listen('hash-progress', (event: any) => {
        const payload = event.payload as any;
        if (payload.file === filePath) {
          setProgress({ 
            percent: payload.percent || 0, 
            bytes_read: payload.bytes_read || 0, 
            total: payload.total || 0 
          });
        }
      });
    })();

    return () => {
      if (unlisten && typeof unlisten.then === 'function') {
        unlisten.then((f: any) => f());
      }
    };
  }, [filePath]);

  const handleSaveReport = async () => {
    if (!filePath) {
      showAlert(t('saveReport'), t('selectFileBeforeSave'));
      return;
    }

    const targetPath = await save({
      title: t('saveFileHashReport'),
      defaultPath: 'hash-report.csv',
      filters: [
        { name: 'CSV', extensions: ['csv'] },
        { name: 'JSON', extensions: ['json'] }
      ],
    });

    if (!targetPath || targetPath.length === 0) {
      return;
    }

    const format = targetPath.endsWith('.json') ? 'json' : 'csv';

    let reportItem: any = {
      name: filePath.split(/[/\\]/).pop() || '',
      path: filePath,
      md5: md5 || '',
      sha1: sha1 || '',
      sha256: sha256 || '',
      sha384: sha384 || '',
      sha512: sha512 || '',
      sha3_256: sha3_256 || '',
      sha3_512: sha3_512 || '',
      blake2b: blake2b || '',
      blake2s: blake2s || '',
      blake3: blake3 || '',
      crc32: crc32 || '',
      crc64: crc64 || '',
      xxhash3: xxhash3 || '',
    };

    if (excludeEmptyFields) {
      reportItem = Object.fromEntries(Object.entries(reportItem).filter(([_, v]) => v !== ''));
    }

    const reportData = [reportItem];

    try {
      const dataToSave = format === 'json' ? 
        JSON.stringify(reportData[0], null, 2) : // keep original format for JSON (single object)
        JSON.stringify(reportData);              // use array for CSV deserialization
      await invoke('save_report', { filePath: targetPath, data: dataToSave, format: format });
      showAlert(t('saveReport'), t('reportSaved', { path: targetPath }));
    } catch (error) {
      console.error('Failed to save report', error);
      showAlert(t('error'), t('reportSaveFailed', { error: String(error) }));
    }
  };

  const handleVerifyHash = async () => {
    if (!filePath || !expectedHash.trim()) {
      showAlert(t('verification'), t('selectFileAndHash'));
      return;
    }
    const calculatedHashes = {
      md5: md5,
      sha1: sha1,
      sha256: sha256,
      sha512: sha512,
      sha384: sha384,
      sha3_256: sha3_256,
      sha3_512: sha3_512,
      blake2b: blake2b,
      blake2s: blake2s,
      blake3: blake3,
      crc32: crc32,
      crc64: crc64,
      xxhash3: xxhash3,
    };
    const isMatch = await invoke("verify_hash", { expectedHash: expectedHash.trim(), calculatedHashes });
    if (isMatch) {
      showAlert(t('verification'), t('hashMatches'), 'success');
    } else {
      showAlert(t('verification'), t('hashDoesNotMatch'), 'error');
    }
  };


  const [copied, setCopied] = useState<Record<AlgorithmKey, boolean>>({ md5: false, sha1: false, sha256: false, sha384: false, sha512: false, sha3_256: false, sha3_512: false, blake2b: false, blake2s: false, blake3: false, crc32: false, crc64: false, xxhash3: false });

  const handleCopy = async (key: AlgorithmKey, value: string) => {
  if (!value) return;
  try {
    await navigator.clipboard.writeText(value);
    setCopied(prev => ({ ...prev, [key]: true }));
    setTimeout(() => setCopied(prev => ({ ...prev, [key]: false })), 2000);
  } catch (e) {
    console.error('Copy failed', e);
  }
  };

  const additionalHashValues: Record<AlgorithmKey, string> = {
    md5, sha1, sha256, sha384, sha512, sha3_256, sha3_512, blake2b, blake2s, blake3, crc32, crc64, xxhash3,
  };

  return (
    <Box sx={{ p: 1 }}> 
      {/* File Selection Row */}
      <Grid container spacing={1} alignItems="center" sx={{ mb: 2 }}>
        <Grid item xs={10}>
          <TextField label={t('file')} value={filePath} fullWidth size="small" InputProps={{ readOnly: true }} />
        </Grid>
        <Grid item xs={2}>
          <Button variant="contained" onClick={() => handleFileSelect()} fullWidth size="small" disabled={isHashing}>{t('browse')}</Button>
        </Grid>
      </Grid>

      {/* Algorithm Selection */}
      <Typography variant="subtitle2" sx={{ mb: 1 }}>{t('hashAlgorithms')}</Typography>
      <Grid container spacing={1} sx={{ mb: 2 }}>
        <Grid item xs={6}>
          <FormControlLabel 
            control={<Checkbox checked={selectedAlgorithms.md5} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('md5', checked)} size="small" />} 
            label="MD5" 
          />
        </Grid>
        <Grid item xs={6}>
          <FormControlLabel 
            control={<Checkbox checked={selectedAlgorithms.sha1} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('sha1', checked)} size="small" />} 
            label="SHA-1" 
          />
        </Grid>
        <Grid item xs={6}>
          <FormControlLabel 
            control={<Checkbox checked={selectedAlgorithms.sha256} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('sha256', checked)} size="small" />} 
            label="SHA-256" 
          />
        </Grid>
        <Grid item xs={6}>
          <FormControlLabel control={<Checkbox checked={selectedAlgorithms.sha384} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('sha384', checked)} size="small" />} label="SHA-384" />
        </Grid>
        <Grid item xs={6}>
          <FormControlLabel 
            control={<Checkbox checked={selectedAlgorithms.sha512} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('sha512', checked)} size="small" />} 
            label="SHA-512" 
          />
        </Grid>
        <Grid item xs={6}>
          <FormControlLabel control={<Checkbox checked={selectedAlgorithms.sha3_256} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('sha3_256', checked)} size="small" />} label="SHA3-256" />
        </Grid>
        <Grid item xs={6}>
          <FormControlLabel control={<Checkbox checked={selectedAlgorithms.sha3_512} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('sha3_512', checked)} size="small" />} label="SHA3-512" />
        </Grid>
        <Grid item xs={6}>
          <FormControlLabel control={<Checkbox checked={selectedAlgorithms.blake2b} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('blake2b', checked)} size="small" />} label="BLAKE2b" />
        </Grid>
        <Grid item xs={6}>
          <FormControlLabel control={<Checkbox checked={selectedAlgorithms.blake2s} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('blake2s', checked)} size="small" />} label="BLAKE2s" />
        </Grid>
        <Grid item xs={6}>
          <FormControlLabel 
            control={<Checkbox checked={selectedAlgorithms.blake3} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('blake3', checked)} size="small" />} 
            label="BLAKE3" 
          />
        </Grid>
        <Grid item xs={6}>
          <FormControlLabel 
            control={<Checkbox checked={selectedAlgorithms.xxhash3} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('xxhash3', checked)} size="small" />} 
            label="XXHash3" 
          />
        </Grid>
        <Grid item xs={6}>
          <FormControlLabel control={<Checkbox checked={selectedAlgorithms.crc32} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('crc32', checked)} size="small" />} label="CRC32" />
        </Grid>
        <Grid item xs={6}>
          <FormControlLabel control={<Checkbox checked={selectedAlgorithms.crc64} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('crc64', checked)} size="small" />} label="CRC64" />
        </Grid>
      </Grid>

      {/* Hash Results - Only show selected algorithms */}
      <Typography variant="subtitle2" sx={{ mb: 1 }}>{t('hashResults')}</Typography>
      <Grid container spacing={1}>
        {selectedAlgorithms.md5 && (
          <>
            <Grid item xs={2}>
              <Typography variant="body2" sx={{ mt: 1 }}>MD5:</Typography>
            </Grid>
            <Grid item xs={9}>
              <TextField value={md5} fullWidth size="small" InputProps={{ readOnly: true }} />
            </Grid>
            <Grid item xs={1}>
              <IconButton color={copied.md5 ? 'success' : 'default'} onClick={() => handleCopy('md5', md5)} aria-label="copy md5" size="small">
                {copied.md5 ? <CheckCircleIcon fontSize="small" /> : <ContentCopyIcon fontSize="small" />}
              </IconButton>
            </Grid>
          </>
        )}

        {selectedAlgorithms.sha1 && (
          <>
            <Grid item xs={2}>
              <Typography variant="body2" sx={{ mt: 1 }}>SHA-1:</Typography>
            </Grid>
            <Grid item xs={9}>
              <TextField value={sha1} fullWidth size="small" InputProps={{ readOnly: true }} />
            </Grid>
            <Grid item xs={1}>
              <IconButton color={copied.sha1 ? 'success' : 'default'} onClick={() => handleCopy('sha1', sha1)} aria-label="copy sha1" size="small">
                {copied.sha1 ? <CheckCircleIcon fontSize="small" /> : <ContentCopyIcon fontSize="small" />}
              </IconButton>
            </Grid>
          </>
        )}

        {selectedAlgorithms.sha256 && (
          <>
            <Grid item xs={2}>
              <Typography variant="body2" sx={{ mt: 1 }}>SHA-256:</Typography>
            </Grid>
            <Grid item xs={9}>
              <TextField value={sha256} fullWidth size="small" InputProps={{ readOnly: true }} />
            </Grid>
            <Grid item xs={1}>
              <IconButton color={copied.sha256 ? 'success' : 'default'} onClick={() => handleCopy('sha256', sha256)} aria-label="copy sha256" size="small">
                {copied.sha256 ? <CheckCircleIcon fontSize="small" /> : <ContentCopyIcon fontSize="small" />}
              </IconButton>
            </Grid>
          </>
        )}

        {selectedAlgorithms.sha512 && (
          <>
            <Grid item xs={2}>
              <Typography variant="body2" sx={{ mt: 1 }}>SHA-512:</Typography>
            </Grid>
            <Grid item xs={9}>
              <TextField value={sha512} fullWidth size="small" InputProps={{ readOnly: true }} />
            </Grid>
            <Grid item xs={1}>
              <IconButton color={copied.sha512 ? 'success' : 'default'} onClick={() => handleCopy('sha512', sha512)} aria-label="copy sha512" size="small">
                {copied.sha512 ? <CheckCircleIcon fontSize="small" /> : <ContentCopyIcon fontSize="small" />}
              </IconButton>
            </Grid>
          </>
        )}

        {(['sha384', 'sha3_256', 'sha3_512', 'blake2b', 'blake2s', 'crc32', 'crc64'] as AlgorithmKey[]).map((key) => selectedAlgorithms[key] && (
          <Fragment key={key}>
            <Grid item xs={2}><Typography variant="body2" sx={{ mt: 1 }}>{key === 'sha3_256' ? 'SHA3-256' : key === 'sha3_512' ? 'SHA3-512' : key === 'blake2b' ? 'BLAKE2b' : key === 'blake2s' ? 'BLAKE2s' : key.toUpperCase()}:</Typography></Grid>
            <Grid item xs={9}><TextField value={additionalHashValues[key]} fullWidth size="small" InputProps={{ readOnly: true }} /></Grid>
            <Grid item xs={1}><IconButton color={copied[key] ? 'success' : 'default'} onClick={() => handleCopy(key, additionalHashValues[key])} aria-label={`copy ${key}`} size="small">{copied[key] ? <CheckCircleIcon fontSize="small" /> : <ContentCopyIcon fontSize="small" />}</IconButton></Grid>
          </Fragment>
        ))}

        {selectedAlgorithms.blake3 && (
          <>
            <Grid item xs={2}>
              <Typography variant="body2" sx={{ mt: 1 }}>BLAKE3:</Typography>
            </Grid>
            <Grid item xs={9}>
              <TextField value={blake3} fullWidth size="small" InputProps={{ readOnly: true }} />
            </Grid>
            <Grid item xs={1}>
              <IconButton color={copied.blake3 ? 'success' : 'default'} onClick={() => handleCopy('blake3', blake3)} aria-label="copy blake3" size="small">
                {copied.blake3 ? <CheckCircleIcon fontSize="small" /> : <ContentCopyIcon fontSize="small" />}
              </IconButton>
            </Grid>
          </>
        )}

        {selectedAlgorithms.xxhash3 && (
          <>
            <Grid item xs={2}>
              <Typography variant="body2" sx={{ mt: 1 }}>XXHash3:</Typography>
            </Grid>
            <Grid item xs={9}>
              <TextField value={xxhash3} fullWidth size="small" InputProps={{ readOnly: true }} />
            </Grid>
            <Grid item xs={1}>
              <IconButton color={copied.xxhash3 ? 'success' : 'default'} onClick={() => handleCopy('xxhash3', xxhash3)} aria-label="copy xxhash3" size="small">
                {copied.xxhash3 ? <CheckCircleIcon fontSize="small" /> : <ContentCopyIcon fontSize="small" />}
              </IconButton>
            </Grid>
          </>
        )}

        {progress && (
          <Grid item xs={12} sx={{ mt: 1, mb: 1 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Box sx={{ flex: 1 }}>
                <LinearProgress variant="determinate" value={Math.min(Math.max(progress.percent, 0), 100)} />
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mt: 0.5 }}>
                  <Typography variant="caption">{`${Math.round(progress.percent)}%`}</Typography>
                  {progress.total > 0 && (
                    <Typography variant="caption">{`${(progress.bytes_read / (1024*1024)).toFixed(2)} MB / ${(progress.total / (1024*1024*1024)).toFixed(2)} GB`}</Typography>
                  )}
                </Box>
              </Box>
              <Box>
                <Button variant="outlined" color="error" size="small" onClick={async () => { await invoke('cancel_hashing'); setIsHashing(false); setProgress(null); }}>{t('cancel')}</Button>
              </Box>
            </Box>
          </Grid>
        )}
      </Grid>

      {/* Verify Section */}
      <Box sx={{ mt: 2 }}>
        <Typography variant="subtitle2">{t('verifyHash')}</Typography>
        <TextField
          placeholder={t('pasteHash')}
          value={expectedHash}
          onChange={(event: React.ChangeEvent<HTMLInputElement>) => setExpectedHash(event.target.value)}
          fullWidth
          size="small"
          sx={{ mt: 1 }}
        />
        <Button variant="contained" onClick={handleVerifyHash} fullWidth sx={{ mt: 1 }} size="small" disabled={isHashing}>{t('verify')}</Button>
      </Box>

      <FormControlLabel
        control={<Checkbox size="small" checked={excludeEmptyFields} onChange={(e) => setExcludeEmptyFields(e.target.checked)} />}
        label={<Typography variant="body2">{t('excludeEmptyFields')}</Typography>}
      />
      <Button variant="contained" onClick={handleSaveReport} fullWidth sx={{ mt: 1 }} size="small">{t('saveReport')}</Button>
    </Box>
  );
};

interface GpgVerifyTabProps {
  showAlert: (title: string, message: string) => void;
  t: (key: TranslationKey, values?: Record<string, string>) => string;
}

const GpgVerifyTab = ({ showAlert, t }: GpgVerifyTabProps) => {
  const [filePath, setFilePath] = useState("");
  const [signaturePath, setSignaturePath] = useState("");
  const [expectedFingerprint, setExpectedFingerprint] = useState("");
  const [gpgResult, setGpgResult] = useState<GpgVerificationResult | null>(null);
  const [isVerifyingGpg, setIsVerifyingGpg] = useState(false);

  const handleFileSelect = async () => {
    const selectedPath = await openDialog({ multiple: false });
    if (typeof selectedPath === 'string') {
      setFilePath(selectedPath);
    }
  };

  const handleSignatureSelect = async () => {
    const selectedPath = await openDialog({ multiple: false });
    if (typeof selectedPath === 'string') {
      setSignaturePath(selectedPath);
    }
  };

  const handleVerifyGpg = async () => {
    if (!filePath) {
      showAlert(t('gpgVerification'), t('selectFileBeforeSignature'));
      return;
    }
    if (!signaturePath) {
      showAlert(t('gpgVerification'), t('selectSignatureFile'));
      return;
    }

    setIsVerifyingGpg(true);
    setGpgResult(null);

    try {
      const result = await invoke<GpgVerificationResult>('verify_gpg_signature', {
        filePath,
        signaturePath,
        expectedFingerprint: expectedFingerprint.trim() || null,
      });
      setGpgResult(result);
    } catch (error) {
      console.error('GPG verification failed:', error);
      showAlert(t('gpgVerification'), t('gpgVerificationFailed', { error: String(error) }));
    } finally {
      setIsVerifyingGpg(false);
    }
  };

  return (
    <Box sx={{ p: 1 }}>
      <Grid container spacing={1} alignItems="center" sx={{ mb: 2 }}>
        <Grid item xs={10}>
          <TextField label={t('file')} value={filePath} fullWidth size="small" InputProps={{ readOnly: true }} />
        </Grid>
        <Grid item xs={2}>
          <Button variant="contained" onClick={handleFileSelect} fullWidth size="small" disabled={isVerifyingGpg}>{t('browse')}</Button>
        </Grid>
      </Grid>

      <Typography variant="subtitle2">{t('detachedSignatureFile')}</Typography>
      <Grid container spacing={1} alignItems="center" sx={{ mt: 0.5 }}>
        <Grid item xs={10}>
          <TextField
            placeholder={t('detachedSignaturePlaceholder')}
            value={signaturePath}
            fullWidth
            size="small"
            InputProps={{ readOnly: true }}
          />
        </Grid>
        <Grid item xs={2}>
          <Button variant="contained" onClick={handleSignatureSelect} fullWidth size="small" disabled={isVerifyingGpg}>{t('browse')}</Button>
        </Grid>
      </Grid>

      <TextField
        label={t('expectedFingerprint')}
        value={expectedFingerprint}
        onChange={(event: React.ChangeEvent<HTMLInputElement>) => setExpectedFingerprint(event.target.value)}
        fullWidth
        size="small"
        sx={{ mt: 2 }}
      />

      <Button
        variant="contained"
        onClick={handleVerifyGpg}
        fullWidth
        sx={{ mt: 2 }}
        size="small"
        disabled={isVerifyingGpg}
      >
        {isVerifyingGpg ? t('verifyingSignature') : t('verifyGpgSignature')}
      </Button>

      {gpgResult && (
        <Box sx={{ mt: 2, p: 1, border: 1, borderColor: 'divider', borderRadius: 1 }}>
          <Typography variant="body2" color={gpgResult.valid_signature && gpgResult.fingerprint_match ? 'success.main' : 'error.main'}>
            {gpgResult.message}
          </Typography>
          <Typography variant="body2" sx={{ mt: 0.5 }}>{t('signatureValid')} {gpgResult.valid_signature ? 'Yes' : 'No'}</Typography>
          <Typography variant="body2">{t('fingerprintMatch')} {gpgResult.fingerprint_match ? 'Yes' : 'No'}</Typography>
          {gpgResult.signer && <Typography variant="body2">{t('signer')} {gpgResult.signer}</Typography>}
          {gpgResult.fingerprint && <Typography variant="body2">{t('fingerprint')} {gpgResult.fingerprint}</Typography>}
          {gpgResult.trust_level && <Typography variant="body2">{t('trustLevel')} {gpgResult.trust_level}</Typography>}
        </Box>
      )}
    </Box>
  );
};

interface FolderScanTabProps {
    folderPath: string;
    setFolderPath: (path: string) => void;
    selectedAlgorithms: { [key: string]: boolean };
    handleAlgorithmChange: (algorithm: string, checked: boolean) => void;
    showAlert: (title: string, message: string) => void;
    excludeEmptyFields: boolean;
    setExcludeEmptyFields: (value: boolean) => void;
    t: (key: TranslationKey, values?: Record<string, string>) => string;
}

const FileResultItem = ({ file, selectedAlgorithms }: { file: any, selectedAlgorithms: any }) => {
  const [copied, setCopied] = useState<Record<AlgorithmKey, boolean>>({ md5: false, sha1: false, sha256: false, sha384: false, sha512: false, sha3_256: false, sha3_512: false, blake2b: false, blake2s: false, blake3: false, crc32: false, crc64: false, xxhash3: false });

  const handleCopy = async (key: AlgorithmKey, value: string) => {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      setCopied(prev => ({ ...prev, [key]: true }));
      setTimeout(() => setCopied(prev => ({ ...prev, [key]: false })), 2000);
    } catch (e) {
      console.error('Failed to copy text: ', e);
    }
  };

  const renderHashRow = (label: string, key: AlgorithmKey) => {
    if (!selectedAlgorithms[key]) return null;
    return (
      <Grid container spacing={0.5} alignItems="center" sx={{ mt: 0.5 }}>
        <Grid item xs={2}>
          <Typography variant="caption" sx={{ fontWeight: 'bold' }}>{label}:</Typography>
        </Grid>
        <Grid item xs={9}>
          <TextField value={file[key] || ''} fullWidth size="small" InputProps={{ readOnly: true, sx: { fontSize: '0.75rem', padding: '2px' } }} variant="standard" />
        </Grid>
        <Grid item xs={1}>
          <IconButton color={copied[key] ? 'success' : 'default'} onClick={() => handleCopy(key, file[key] || '')} aria-label={`copy ${key}`} size="small" sx={{ padding: '2px' }}>
            {copied[key] ? <CheckCircleIcon sx={{ fontSize: 16 }} /> : <ContentCopyIcon sx={{ fontSize: 16 }} />}
          </IconButton>
        </Grid>
      </Grid>
    );
  };

  return (
    <Paper sx={{ p: 1.5, mb: 1.5 }} elevation={1}>
      <Typography variant="body2" sx={{ fontWeight: 'bold' }}>{file.name}</Typography>
      <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 1, wordBreak: 'break-all' }}>{file.path}</Typography>
      {renderHashRow('MD5', 'md5')}
      {renderHashRow('SHA-1', 'sha1')}
      {renderHashRow('SHA-256', 'sha256')}
      {renderHashRow('SHA-384', 'sha384')}
      {renderHashRow('SHA-512', 'sha512')}
      {renderHashRow('SHA3-256', 'sha3_256')}
      {renderHashRow('SHA3-512', 'sha3_512')}
      {renderHashRow('BLAKE2b', 'blake2b')}
      {renderHashRow('BLAKE2s', 'blake2s')}
      {renderHashRow('BLAKE3', 'blake3')}
      {renderHashRow('CRC32', 'crc32')}
      {renderHashRow('CRC64', 'crc64')}
      {renderHashRow('XXHash3', 'xxhash3')}
    </Paper>
  );
};

const FolderScanTab = ({ folderPath, setFolderPath, selectedAlgorithms, handleAlgorithmChange, showAlert, excludeEmptyFields, setExcludeEmptyFields, t }: FolderScanTabProps) => {
  const [files, setFiles] = useState<any[]>([]);
  const [includeSubfolders, setIncludeSubfolders] = useState(true);
  const [includeHidden, setIncludeHidden] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState<{ completed: number; total: number } | null>(null);

  useEffect(() => {
    let unlisten: any;
    (async () => {
      unlisten = await listen('folder-scan-progress', (event: any) => {
        const payload = event.payload as any;
        setProgress({ 
          completed: payload.completed || 0, 
          total: payload.total || 0 
        });
      });
    })();

    return () => {
      if (unlisten && typeof unlisten.then === 'function') {
        unlisten.then((f: any) => f());
      }
    };
  }, []);

  const handleFolderSelect = async () => {
    const selected = await openDialog({
      directory: true,
      multiple: false,
    });
    if (typeof selected === 'string') {
      setFolderPath(selected);
    }
  };

  const handleScan = async () => {
    // Get only selected algorithms for folder scan
    const algorithms = Object.keys(selectedAlgorithms).filter(key => selectedAlgorithms[key]);
    
    if (algorithms.length === 0) {
      showAlert(t('error'), t('selectAlgorithm'));
      return;
    }
    
    setIsScanning(true);
    setProgress({ completed: 0, total: 100 }); // Indeterminate at first, total won't be 100 actually unless 100 files, but we update soon
    setFiles([]);
    try {
      const scannedFiles = await invoke("scan_folder", { 
        folderPath, 
        includeSubfolders, 
        includeHidden,
        algorithms 
      });
      setFiles(scannedFiles as any[]);
    } catch (e) {
      if (e !== "Cancelled") showAlert(t('error'), t('folderScanFailed', { error: String(e) }));
    } finally {
      setIsScanning(false);
      setProgress(null);
    }
  };

  const handleSaveReport = async () => {
    if (!files.length) {
      showAlert(t('saveFolderResults'), t('scanBeforeSave'));
      return;
    }

    const targetPath = await save({
      title: t('saveFolderResults'),
      defaultPath: 'folder-hash-results.csv',
      filters: [
        { name: 'CSV', extensions: ['csv'] },
        { name: 'JSON', extensions: ['json'] }
      ],
    });

    if (!targetPath || targetPath.length === 0) {
      return;
    }

    try {
      const format = targetPath.endsWith('.json') ? 'json' : 'csv';
      
      let reportData = files;
      if (excludeEmptyFields) {
        reportData = files.map(file => Object.fromEntries(Object.entries(file).filter(([_, v]) => v !== '')));
      }

      const jsonData = JSON.stringify(reportData, null, 2);
      await invoke('save_report', { filePath: targetPath, data: jsonData, format });
      showAlert(t('saveFolderResults'), t('folderResultsSaved', { path: targetPath }));
    } catch (error) {
      console.error('Failed to save folder results', error);
      showAlert(t('error'), t('folderResultsSaveFailed', { error: String(error) }));
    }
  };

  return (
    <Box sx={{ p: 2 }}> 
        <Grid container spacing={2} alignItems="center">
            <Grid item xs={10}>
                <TextField label={t('folder')} value={folderPath} fullWidth InputProps={{ readOnly: true }} />
            </Grid>
            <Grid item xs={2}>
                <Button variant="contained" onClick={handleFolderSelect} fullWidth>{t('browse')}</Button>
            </Grid>
        </Grid>

        <Box sx={{ mt: 2 }}>
            <Typography variant="h6" sx={{ mb: 1 }}>{t('algorithmSelection')}</Typography>
            <Grid container spacing={1}>
              <Grid item xs={4}>
                <FormControlLabel 
                  control={<Checkbox checked={selectedAlgorithms.md5} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('md5', checked)} size="small" />} 
                  label="MD5" 
                />
              </Grid>
              <Grid item xs={4}>
                <FormControlLabel 
                  control={<Checkbox checked={selectedAlgorithms.sha1} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('sha1', checked)} size="small" />} 
                  label="SHA-1" 
                />
              </Grid>
              <Grid item xs={4}>
                <FormControlLabel 
                  control={<Checkbox checked={selectedAlgorithms.sha256} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('sha256', checked)} size="small" />} 
                  label="SHA-256" 
                />
              </Grid>
              <Grid item xs={4}><FormControlLabel control={<Checkbox checked={selectedAlgorithms.sha384} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('sha384', checked)} size="small" />} label="SHA-384" /></Grid>
              <Grid item xs={4}>
                <FormControlLabel 
                  control={<Checkbox checked={selectedAlgorithms.sha512} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('sha512', checked)} size="small" />} 
                  label="SHA-512" 
                />
              </Grid>
              <Grid item xs={4}><FormControlLabel control={<Checkbox checked={selectedAlgorithms.sha3_256} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('sha3_256', checked)} size="small" />} label="SHA3-256" /></Grid>
              <Grid item xs={4}><FormControlLabel control={<Checkbox checked={selectedAlgorithms.sha3_512} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('sha3_512', checked)} size="small" />} label="SHA3-512" /></Grid>
              <Grid item xs={4}><FormControlLabel control={<Checkbox checked={selectedAlgorithms.blake2b} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('blake2b', checked)} size="small" />} label="BLAKE2b" /></Grid>
              <Grid item xs={4}><FormControlLabel control={<Checkbox checked={selectedAlgorithms.blake2s} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('blake2s', checked)} size="small" />} label="BLAKE2s" /></Grid>
              <Grid item xs={4}>
                <FormControlLabel 
                  control={<Checkbox checked={selectedAlgorithms.blake3} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('blake3', checked)} size="small" />} 
                  label="BLAKE3" 
                />
              </Grid>
              <Grid item xs={4}>
                <FormControlLabel 
                  control={<Checkbox checked={selectedAlgorithms.xxhash3} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('xxhash3', checked)} size="small" />} 
                  label="XXHash3" 
                />
              </Grid>
              <Grid item xs={4}><FormControlLabel control={<Checkbox checked={selectedAlgorithms.crc32} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('crc32', checked)} size="small" />} label="CRC32" /></Grid>
              <Grid item xs={4}><FormControlLabel control={<Checkbox checked={selectedAlgorithms.crc64} onChange={(_event: unknown, checked: boolean) => handleAlgorithmChange('crc64', checked)} size="small" />} label="CRC64" /></Grid>
            </Grid>
            <FormControlLabel control={<Checkbox checked={includeSubfolders} onChange={() => setIncludeSubfolders(!includeSubfolders)} />} label={t('includeSubfolders')} />
            <FormControlLabel control={<Checkbox checked={includeHidden} onChange={() => setIncludeHidden(!includeHidden)} />} label={t('includeHiddenFiles')} />
        </Box>

        <Box sx={{ mt: 2, display: 'flex', gap: 1 }}>
          <Button variant="contained" onClick={handleScan} fullWidth disabled={isScanning}>{t('scanFolder')}</Button>
          {isScanning && (
            <Button variant="outlined" color="error" onClick={() => invoke('cancel_hashing')}>{t('cancel')}</Button>
          )}
        </Box>
        {isScanning && progress && (
          <Box sx={{ mt: 2 }}>
            <LinearProgress variant={progress.total > 0 ? "determinate" : "indeterminate"} value={progress.total > 0 ? (progress.completed / progress.total) * 100 : 0} />
            <Typography variant="caption" sx={{ mt: 0.5, display: 'block', textAlign: 'center' }}>
              {progress.total > 0 ? t('filesCompleted', { completed: String(progress.completed), total: String(progress.total), percent: String(Math.round((progress.completed / progress.total) * 100)) }) : t('scanning')}
            </Typography>
          </Box>
        )}

        <Box sx={{ mt: 3 }}>
          {files.map((file, index) => (
             <FileResultItem key={index} file={file} selectedAlgorithms={selectedAlgorithms} />
          ))}
        </Box>

        <FormControlLabel
          control={<Checkbox size="small" checked={excludeEmptyFields} onChange={(e) => setExcludeEmptyFields(e.target.checked)} />}
          label={<Typography variant="body2">{t('excludeEmptyFields')}</Typography>}
        />
        <Button variant="contained" onClick={handleSaveReport} fullWidth sx={{ mt: 2 }}>{t('saveFolderResults')}</Button>
    </Box>
  );
};

export default App;
